use native_tls::TlsConnector;

use crate::smtp_verify::dns::{HostCandidate, build_resolver, resolve_hosts};
use crate::smtp_verify::error::SmtpVerifyError;
use crate::smtp_verify::options::SmtpProbeOptions;
use crate::smtp_verify::session::{SmtpReply, SmtpSession};
use crate::smtp_verify::types::{Existence, SmtpProbeReport};
use crate::smtp_verify::util::{confidence_for, random_local_part};
use crate::validator::{ValidationMode, normalize_email};

pub fn check_mailaddress_exists(
    addr: &str,
    options: &SmtpProbeOptions,
) -> Result<SmtpProbeReport, SmtpVerifyError> {
    let normalized = normalize_email(addr, ValidationMode::Strict)
        .map_err(|err| SmtpVerifyError::Protocol(err.to_string()))?;

    if !normalized.valid {
        return Err(SmtpVerifyError::invalid_email(normalized.reasons.clone()));
    }

    let local = normalized.local.clone();
    let domain = if !normalized.ascii_domain.is_empty() {
        normalized.ascii_domain.clone()
    } else if !normalized.domain.is_empty() {
        idna::domain_to_ascii(&normalized.domain).map_err(SmtpVerifyError::idna)?
    } else {
        return Err(SmtpVerifyError::InvalidEmail {
            reasons: vec!["domain missing".to_string()],
        });
    };

    let resolver = build_resolver()?;
    let hosts = resolve_hosts(&resolver, &domain, options.max_mx, options.ipv6)?;

    if hosts.is_empty() {
        return Err(SmtpVerifyError::NoSmtpServers);
    }

    let connector = TlsConnector::new().map_err(|err| SmtpVerifyError::Tls { source: err })?;

    let fallback_mail_from = format!("postmaster@{domain}");
    let mail_from = options.mail_from(&fallback_mail_from).into_owned();
    let helo = options.helo_name(&domain);

    let catchall_count = options.catchall_probes.min(5);
    let catchall_locals: Vec<String> = (0..catchall_count)
        .map(|_| random_local_part(local.len()))
        .collect();

    let mut mx_tried = Vec::new();
    let mut transcripts = Vec::new();
    let mut last_result = Existence::Indeterminate("no server responded".to_string());

    for candidate in hosts {
        mx_tried.push(candidate.host.clone());
        match probe_host(
            &candidate,
            &TargetAddress {
                local: &local,
                domain: &domain,
            },
            options,
            &connector,
            &mail_from,
            helo.as_ref(),
            &catchall_locals,
        ) {
            Ok(host_report) => {
                transcripts.extend(host_report.transcript);
                match host_report.existence {
                    Existence::Exists | Existence::DoesNotExist => {
                        let confidence = confidence_for(&host_report.existence);
                        return Ok(SmtpProbeReport::new(
                            host_report.existence,
                            mx_tried,
                            transcripts,
                            confidence,
                        ));
                    }
                    other => {
                        last_result = other;
                    }
                }
            }
            Err(err) => {
                transcripts.push(format!("[{}] ! error: {err}", candidate.host));
                last_result = Existence::Indeterminate(err.to_string());
            }
        }
    }

    let confidence = confidence_for(&last_result);
    Ok(SmtpProbeReport::new(
        last_result,
        mx_tried,
        transcripts,
        confidence,
    ))
}

struct TargetAddress<'a> {
    local: &'a str,
    domain: &'a str,
}

struct HostReport {
    existence: Existence,
    transcript: Vec<String>,
}

fn probe_host(
    candidate: &HostCandidate,
    target: &TargetAddress<'_>,
    options: &SmtpProbeOptions,
    connector: &TlsConnector,
    mail_from: &str,
    helo: &str,
    catchall_locals: &[String],
) -> Result<HostReport, SmtpVerifyError> {
    let mut session =
        SmtpSession::connect(&candidate.host, &candidate.addresses, options.timeout())?;
    let banner = session.read_banner()?;
    if banner.code == 521 {
        session.quit().ok();
        let transcript = std::mem::take(&mut session.transcript);
        return Ok(HostReport {
            existence: Existence::Indeterminate("server does not receive mail".to_string()),
            transcript,
        });
    }

    let helo_cmd = format!("EHLO {helo}");
    let ehlo = session.send_command(&helo_cmd)?;

    let starttls_advertised = ehlo.has_capability("STARTTLS");
    if options.starttls_required && !starttls_advertised {
        session.quit().ok();
        let transcript = std::mem::take(&mut session.transcript);
        return Ok(HostReport {
            existence: Existence::Indeterminate(format!(
                "STARTTLS required but not offered by {}",
                candidate.host
            )),
            transcript,
        });
    }

    if starttls_advertised {
        let tls_reply = session.starttls(&candidate.host, connector, options.timeout())?;
        if !tls_reply.is_positive_completion() {
            session.quit().ok();
            let transcript = std::mem::take(&mut session.transcript);
            return Ok(HostReport {
                existence: Existence::Indeterminate(format!(
                    "STARTTLS rejected by {} (code {})",
                    candidate.host, tls_reply.code
                )),
                transcript,
            });
        }
        // EHLO again over TLS
        let _ = session.send_command(&helo_cmd)?;
    }

    let envelope = if mail_from.is_empty() {
        "MAIL FROM:<>".to_string()
    } else {
        format!("MAIL FROM:<{}>", mail_from)
    };
    let mail_reply = session.send_command(&envelope)?;
    if mail_reply.is_permanent_failure() {
        session.quit().ok();
        let transcript = std::mem::take(&mut session.transcript);
        return Ok(HostReport {
            existence: Existence::Indeterminate(format!(
                "MAIL FROM rejected with {}",
                mail_reply.code
            )),
            transcript,
        });
    }

    let target_cmd = format!("RCPT TO:<{}@{}>", target.local, target.domain);
    let target_reply = session.send_command(&target_cmd)?;
    let existence = classify_target(&target_reply);

    match existence {
        TargetExistence::DoesNotExist => {
            session.quit().ok();
            let transcript = std::mem::take(&mut session.transcript);
            return Ok(HostReport {
                existence: Existence::DoesNotExist,
                transcript,
            });
        }
        TargetExistence::Indeterminate(reason) => {
            session.quit().ok();
            let transcript = std::mem::take(&mut session.transcript);
            return Ok(HostReport {
                existence: Existence::Indeterminate(reason),
                transcript,
            });
        }
        TargetExistence::Accepted => {}
    }

    if catchall_locals.is_empty() {
        session.quit().ok();
        let transcript = std::mem::take(&mut session.transcript);
        return Ok(HostReport {
            existence: Existence::Indeterminate("catch-all probes disabled".to_string()),
            transcript,
        });
    }

    let mut accepted_random = 0usize;
    let mut rejected_random = 0usize;
    let mut tempfail_random = 0usize;

    for alias in catchall_locals {
        if alias.eq(target.local) {
            continue;
        }
        let cmd = format!("RCPT TO:<{}@{}>", alias, target.domain);
        let reply = session.send_command(&cmd)?;
        if reply.is_positive_completion() {
            accepted_random += 1;
        } else if is_permanent_no_mailbox(&reply) {
            rejected_random += 1;
        } else if reply.is_transient_failure() {
            tempfail_random += 1;
        }
    }

    session.send_command("RSET").ok();
    session.quit().ok();

    let existence = if accepted_random > 0 {
        Existence::CatchAll
    } else if rejected_random > 0 && tempfail_random == 0 {
        Existence::Exists
    } else if tempfail_random > 0 {
        Existence::Indeterminate("temporary failure on catch-all probes".to_string())
    } else {
        Existence::Indeterminate("ambiguous catch-all probes".to_string())
    };

    let transcript = std::mem::take(&mut session.transcript);
    Ok(HostReport {
        existence,
        transcript,
    })
}

enum TargetExistence {
    Accepted,
    DoesNotExist,
    Indeterminate(String),
}

fn classify_target(reply: &SmtpReply) -> TargetExistence {
    if reply.is_positive_completion() {
        return TargetExistence::Accepted;
    }
    if is_permanent_no_mailbox(reply) {
        return TargetExistence::DoesNotExist;
    }
    if reply.code == 521 {
        return TargetExistence::Indeterminate("521 host does not accept mail".to_string());
    }
    if reply.is_transient_failure() {
        return TargetExistence::Indeterminate(format!("temporary failure {}", reply.code));
    }
    TargetExistence::Indeterminate(format!("unexpected response {}", reply.code))
}

fn is_permanent_no_mailbox(reply: &SmtpReply) -> bool {
    matches!(reply.code, 550 | 551 | 553)
}
