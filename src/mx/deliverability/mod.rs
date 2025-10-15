mod error;
mod options;
mod session;
mod types;

pub use error::DeliverabilityError;
pub use options::MailboxCheckOptions;
pub use types::{
    AttemptOutcome, AttemptStage, MailboxStatus, MailboxVerification, ServerAttempt, SmtpEvent,
    SmtpReply, VerificationMethod,
};

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

use trust_dns_resolver::Resolver;

use crate::validator::{NormalizedEmail, normalize_email};

use self::types as deliverability_types;
use super::{
    Error as MxError, MxRecord, MxStatus,
    resolver::{self, LookupMx},
};
use deliverability_types::AttemptOutcome::{
    Accepted, NoVerification, ProtocolError, Rejected, TemporaryFailure, Unreachable,
};
use deliverability_types::AttemptStage as Stage;
use deliverability_types::MailboxStatus as Status;
use deliverability_types::MailboxVerification as Verification;
use deliverability_types::ServerAttempt as AttemptRecord;
use deliverability_types::SmtpEvent as Event;
use deliverability_types::VerificationMethod as Method;
use error::DeliverabilityError::EmailNormalization;
use session::SmtpSession;

/// Attempts to confirm that `email` is accepted by at least one SMTP server without
/// delivering a message. The address is normalised, MX records are resolved, and a
/// controlled `VRFY`/`RCPT TO` transcript is executed against the preferred hosts.
pub fn check_mailaddress_exists(email: &str) -> Result<Verification, DeliverabilityError> {
    check_mailaddress_exists_with_options(email, &MailboxCheckOptions::default())
}

/// Identical to [`check_mailaddress_exists`], but allows tweaking timeouts, EHLO identity,
/// and other probing details.
pub fn check_mailaddress_exists_with_options(
    email: &str,
    options: &MailboxCheckOptions,
) -> Result<Verification, DeliverabilityError> {
    let resolver = Resolver::from_system_conf().map_err(MxError::resolver_init)?;
    check_with_resolver(email, options, &resolver)
}

pub(crate) fn check_with_resolver<R: LookupMx>(
    email: &str,
    options: &MailboxCheckOptions,
    resolver_impl: &R,
) -> Result<Verification, DeliverabilityError> {
    let normalized = normalize_email(email, options.validation_mode)
        .map_err(|source| EmailNormalization { source })?;

    if !normalized.valid {
        return Err(DeliverabilityError::invalid_email(normalized.reasons));
    }

    let ascii_domain = effective_ascii_domain(&normalized)?;
    let mx_status = resolver::resolve_with(resolver_impl, &ascii_domain)?;

    let attempts = match mx_status {
        MxStatus::NoRecords => Vec::new(),
        MxStatus::Records(records) => {
            verify_with_records(&normalized, &ascii_domain, options, &records)?
        }
    };

    let status = if attempts.is_empty() {
        Status::NoMailServer
    } else {
        aggregate_status(&attempts)
    };

    Ok(Verification {
        email: normalized.original,
        ascii_domain,
        status,
        attempts,
    })
}

fn effective_ascii_domain(normalized: &NormalizedEmail) -> Result<String, DeliverabilityError> {
    if !normalized.ascii_domain.is_empty() {
        Ok(normalized.ascii_domain.clone())
    } else if !normalized.domain.is_empty() {
        resolver::normalize_domain(&normalized.domain).map_err(DeliverabilityError::from)
    } else {
        Err(DeliverabilityError::invalid_email(vec![
            "missing domain".to_string(),
        ]))
    }
}

fn verify_with_records(
    normalized: &NormalizedEmail,
    ascii_domain: &str,
    options: &MailboxCheckOptions,
    records: &[MxRecord],
) -> Result<Vec<AttemptRecord>, DeliverabilityError> {
    let mut attempts = Vec::new();
    for record in records.iter().take(options.max_servers) {
        let attempt = verify_with_server(normalized, ascii_domain, options, record)?;
        attempts.push(attempt);
        if attempts
            .last()
            .is_some_and(|a| matches!(a.outcome, Accepted { .. }))
        {
            break;
        }
    }
    Ok(attempts)
}

fn verify_with_server(
    normalized: &NormalizedEmail,
    ascii_domain: &str,
    options: &MailboxCheckOptions,
    record: &MxRecord,
) -> Result<AttemptRecord, DeliverabilityError> {
    let mut attempt = AttemptRecord::new(record.exchange.clone());
    let socket_targets = resolve_socket_addrs(&record.exchange, options.port);
    let addrs = match socket_targets {
        Ok(addrs) if !addrs.is_empty() => addrs,
        Ok(_) => {
            attempt.outcome = Unreachable {
                message: "no socket addresses resolved".to_string(),
            };
            return Ok(attempt);
        }
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::Connect,
                message: err.to_string(),
            });
            attempt.outcome = Unreachable {
                message: "failed to resolve socket address".to_string(),
            };
            return Ok(attempt);
        }
    };

    let connect_result =
        SmtpSession::connect(&addrs, options.connect_timeout, options.command_timeout);
    let (mut session, peer_addr) = match connect_result {
        Ok(pair) => pair,
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::Connect,
                message: err.to_string(),
            });
            attempt.outcome = Unreachable {
                message: "connection attempt failed".to_string(),
            };
            return Ok(attempt);
        }
    };
    attempt.address = Some(peer_addr.to_string());

    let greeting = session.read_reply();
    let greeting = match greeting {
        Ok(reply) => {
            attempt.events.push(Event::Received {
                stage: Stage::Greeting,
                reply: reply.clone(),
            });
            reply
        }
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::Greeting,
                message: err.to_string(),
            });
            attempt.outcome = ProtocolError {
                message: "failed to read greeting".to_string(),
            };
            return Ok(attempt);
        }
    };
    if !greeting.is_positive_completion() {
        attempt.outcome = ProtocolError {
            message: format!("unexpected greeting: {}", greeting.code),
        };
        return Ok(attempt);
    }

    let helo = options.helo_domain(ascii_domain);
    let ehlo_cmd = format!("EHLO {helo}");
    attempt.events.push(Event::Sent {
        stage: Stage::Ehlo,
        command: ehlo_cmd.clone(),
    });
    if let Err(err) = session.send_command(&ehlo_cmd, Stage::Ehlo) {
        attempt.events.push(Event::Error {
            stage: Stage::Ehlo,
            message: err.to_string(),
        });
        attempt.outcome = ProtocolError {
            message: "failed to send EHLO".to_string(),
        };
        return Ok(attempt);
    }
    match session.read_reply() {
        Ok(reply) => {
            attempt.events.push(Event::Received {
                stage: Stage::Ehlo,
                reply: reply.clone(),
            });
            if !reply.is_positive_completion() {
                attempt.outcome = ProtocolError {
                    message: format!("EHLO rejected: {}", reply.code),
                };
                return Ok(attempt);
            }
        }
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::Ehlo,
                message: err.to_string(),
            });
            attempt.outcome = ProtocolError {
                message: "no reply to EHLO".to_string(),
            };
            return Ok(attempt);
        }
    }

    let mut fallback = None;

    if options.use_vrfy {
        let vrfy_cmd = format!("VRFY {}", normalized.local);
        attempt.events.push(Event::Sent {
            stage: Stage::Vrfy,
            command: vrfy_cmd.clone(),
        });
        match session.send_command(&vrfy_cmd, Stage::Vrfy) {
            Ok(()) => match session.read_reply() {
                Ok(reply) => {
                    attempt.events.push(Event::Received {
                        stage: Stage::Vrfy,
                        reply: reply.clone(),
                    });
                    if reply.is_positive_completion() {
                        attempt.outcome = Accepted {
                            method: Method::Vrfy,
                            reply,
                        };
                        send_quit(&mut session, &mut attempt);
                        return Ok(attempt);
                    } else if reply.is_permanent_failure() {
                        fallback = Some(Rejected {
                            method: Method::Vrfy,
                            reply,
                        });
                    } else if reply.is_transient_failure() {
                        fallback = Some(TemporaryFailure {
                            method: Method::Vrfy,
                            reply,
                        });
                    }
                }
                Err(err) => {
                    attempt.events.push(Event::Error {
                        stage: Stage::Vrfy,
                        message: err.to_string(),
                    });
                }
            },
            Err(err) => {
                attempt.events.push(Event::Error {
                    stage: Stage::Vrfy,
                    message: err.to_string(),
                });
            }
        }
    }

    let mail_from = format!("MAIL FROM:<{}>", options.envelope_sender(ascii_domain));
    attempt.events.push(Event::Sent {
        stage: Stage::MailFrom,
        command: mail_from.clone(),
    });
    if let Err(err) = session.send_command(&mail_from, Stage::MailFrom) {
        attempt.events.push(Event::Error {
            stage: Stage::MailFrom,
            message: err.to_string(),
        });
        attempt.outcome = ProtocolError {
            message: "failed to send MAIL FROM".to_string(),
        };
        return Ok(attempt);
    }
    let mail_reply = match session.read_reply() {
        Ok(reply) => {
            attempt.events.push(Event::Received {
                stage: Stage::MailFrom,
                reply: reply.clone(),
            });
            reply
        }
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::MailFrom,
                message: err.to_string(),
            });
            attempt.outcome = ProtocolError {
                message: "no reply to MAIL FROM".to_string(),
            };
            return Ok(attempt);
        }
    };
    if mail_reply.is_permanent_failure() {
        attempt.outcome = Rejected {
            method: Method::RcptTo,
            reply: mail_reply,
        };
        send_quit(&mut session, &mut attempt);
        return Ok(attempt);
    } else if mail_reply.is_transient_failure() {
        attempt.outcome = TemporaryFailure {
            method: Method::RcptTo,
            reply: mail_reply,
        };
        send_quit(&mut session, &mut attempt);
        return Ok(attempt);
    }

    let rcpt_cmd = format!("RCPT TO:<{}@{}>", normalized.local, ascii_domain);
    attempt.events.push(Event::Sent {
        stage: Stage::RcptTo,
        command: rcpt_cmd.clone(),
    });
    if let Err(err) = session.send_command(&rcpt_cmd, Stage::RcptTo) {
        attempt.events.push(Event::Error {
            stage: Stage::RcptTo,
            message: err.to_string(),
        });
        attempt.outcome = ProtocolError {
            message: "failed to send RCPT TO".to_string(),
        };
        return Ok(attempt);
    }
    let rcpt_reply = match session.read_reply() {
        Ok(reply) => {
            attempt.events.push(Event::Received {
                stage: Stage::RcptTo,
                reply: reply.clone(),
            });
            reply
        }
        Err(err) => {
            attempt.events.push(Event::Error {
                stage: Stage::RcptTo,
                message: err.to_string(),
            });
            attempt.outcome = ProtocolError {
                message: "no reply to RCPT TO".to_string(),
            };
            return Ok(attempt);
        }
    };

    if rcpt_reply.is_positive_completion() {
        attempt.outcome = Accepted {
            method: Method::RcptTo,
            reply: rcpt_reply,
        };
    } else if rcpt_reply.is_transient_failure() {
        attempt.outcome = TemporaryFailure {
            method: Method::RcptTo,
            reply: rcpt_reply,
        };
    } else if rcpt_reply.is_permanent_failure() {
        attempt.outcome = Rejected {
            method: Method::RcptTo,
            reply: rcpt_reply,
        };
    } else if let Some(fallback_outcome) = fallback {
        attempt.outcome = fallback_outcome;
    } else {
        attempt.outcome = NoVerification {
            message: "RCPT TO response was inconclusive".to_string(),
        };
    }

    send_rset(&mut session, &mut attempt);
    send_quit(&mut session, &mut attempt);
    Ok(attempt)
}

fn resolve_socket_addrs(exchange: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    format!("{exchange}:{port}")
        .to_socket_addrs()
        .map(|iter| iter.collect())
}

fn send_rset(session: &mut SmtpSession, attempt: &mut AttemptRecord) {
    const RSET_CMD: &str = "RSET";
    attempt.events.push(Event::Sent {
        stage: Stage::Rset,
        command: RSET_CMD.to_string(),
    });
    if let Err(err) = session.send_command(RSET_CMD, Stage::Rset) {
        attempt.events.push(Event::Error {
            stage: Stage::Rset,
            message: err.to_string(),
        });
        return;
    }
    match session.read_reply() {
        Ok(reply) => attempt.events.push(Event::Received {
            stage: Stage::Rset,
            reply,
        }),
        Err(err) => attempt.events.push(Event::Error {
            stage: Stage::Rset,
            message: err.to_string(),
        }),
    }
}

fn send_quit(session: &mut SmtpSession, attempt: &mut AttemptRecord) {
    const QUIT_CMD: &str = "QUIT";
    attempt.events.push(Event::Sent {
        stage: Stage::Quit,
        command: QUIT_CMD.to_string(),
    });
    if let Err(err) = session.send_command(QUIT_CMD, Stage::Quit) {
        attempt.events.push(Event::Error {
            stage: Stage::Quit,
            message: err.to_string(),
        });
        return;
    }
    match session.read_reply() {
        Ok(reply) => attempt.events.push(Event::Received {
            stage: Stage::Quit,
            reply,
        }),
        Err(err) => attempt.events.push(Event::Error {
            stage: Stage::Quit,
            message: err.to_string(),
        }),
    }
}

fn aggregate_status(attempts: &[AttemptRecord]) -> Status {
    if attempts
        .iter()
        .any(|attempt| matches!(attempt.outcome, Accepted { .. }))
    {
        return Status::Deliverable;
    }

    if let Some(rejected) = attempts.iter().find_map(|a| match &a.outcome {
        Rejected { reply, .. } => Some(reply),
        _ => None,
    }) {
        return Status::Rejected {
            code: rejected.code,
            message: rejected.message.clone(),
        };
    }

    if let Some(temp) = attempts.iter().find_map(|a| match &a.outcome {
        TemporaryFailure { reply, .. } => Some(reply),
        _ => None,
    }) {
        return Status::TemporaryFailure {
            code: temp.code,
            message: temp.message.clone(),
        };
    }

    if attempts
        .iter()
        .all(|a| matches!(a.outcome, Unreachable { .. }))
    {
        return Status::Unreachable;
    }

    Status::Unverified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mx::tests::StubResolver;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    fn spawn_mock_server(
        script: Vec<(&'static str, &'static str)>,
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("addr").port();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).ok();
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = handle_session(&mut stream, script);
            }
        });
        ready_rx.recv().expect("server ready");
        (port, handle)
    }

    fn handle_session(
        stream: &mut TcpStream,
        script: Vec<(&'static str, &'static str)>,
    ) -> io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        stream.write_all(b"220 mock.smtp.test ESMTP\r\n")?;
        stream.flush()?;
        for (expected, response) in script {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            assert!(
                line.starts_with(expected),
                "expected command starting with '{expected}', got '{line}'"
            );
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
        Ok(())
    }

    fn make_resolver(record: MxRecord) -> StubResolver {
        StubResolver {
            on_lookup: Box::new(move |domain| {
                assert_eq!(domain, "example.com");
                Ok(vec![record.clone()])
            }),
        }
    }

    fn reply(code: u16, message: &str) -> SmtpReply {
        SmtpReply {
            code,
            message: message.to_string(),
        }
    }

    #[test]
    fn invalid_email_rejected() {
        let options = MailboxCheckOptions::default();
        let resolver = StubResolver {
            on_lookup: Box::new(|_| Ok(Vec::new())),
        };
        let err = check_with_resolver("invalid", &options, &resolver).expect_err("should fail");
        assert!(matches!(err, DeliverabilityError::InvalidEmail { .. }));
    }

    #[test]
    fn no_mx_records_reports_no_mail_server() {
        let options = MailboxCheckOptions::default();
        let resolver = StubResolver {
            on_lookup: Box::new(|_| Ok(Vec::new())),
        };
        let result =
            check_with_resolver("user@example.com", &options, &resolver).expect("verification");
        assert!(matches!(result.status, MailboxStatus::NoMailServer));
    }

    #[test]
    fn aggregate_prefers_success_over_rejection() {
        let mut attempt = ServerAttempt::new("mx.example");
        attempt.outcome = AttemptOutcome::Accepted {
            method: VerificationMethod::RcptTo,
            reply: reply(250, "Ok"),
        };
        let status = super::aggregate_status(&[attempt]);
        assert!(matches!(status, MailboxStatus::Deliverable));
    }

    #[test]
    fn aggregate_reports_temporary_failure() {
        let mut attempt = ServerAttempt::new("mx.example");
        attempt.outcome = AttemptOutcome::TemporaryFailure {
            method: VerificationMethod::RcptTo,
            reply: reply(451, "Please try later"),
        };
        let status = super::aggregate_status(&[attempt]);
        match status {
            MailboxStatus::TemporaryFailure { code, .. } => assert_eq!(code, 451),
            other => panic!("expected temporary failure, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires loopback TCP binding"]
    fn delivers_via_rcpt_to() {
        let (port, handle) = spawn_mock_server(vec![
            ("EHLO", "250-mock.example\r\n250 STARTTLS\r\n"),
            ("VRFY", "252 2.0.0 VRFY disabled\r\n"),
            ("MAIL FROM:", "250 2.1.0 Ok\r\n"),
            ("RCPT TO:", "250 2.1.5 Ok\r\n"),
            ("RSET", "250 2.0.0 Reset\r\n"),
            ("QUIT", "221 2.0.0 Bye\r\n"),
        ]);
        let options = MailboxCheckOptions {
            port,
            ..MailboxCheckOptions::default()
        };
        let resolver = make_resolver(MxRecord::new(10, "127.0.0.1"));
        let result =
            check_with_resolver("user@example.com", &options, &resolver).expect("verification");
        assert!(matches!(result.status, MailboxStatus::Deliverable));
        handle.join().expect("server thread");
    }

    #[test]
    #[ignore = "requires loopback TCP binding"]
    fn rcpt_rejected_reports_failure() {
        let (port, handle) = spawn_mock_server(vec![
            ("EHLO", "250 mock.example\r\n"),
            ("VRFY", "252 2.0.0 VRFY disabled\r\n"),
            ("MAIL FROM:", "250 2.1.0 Ok\r\n"),
            ("RCPT TO:", "550 5.1.1 User unknown\r\n"),
            ("RSET", "250 2.0.0 Reset\r\n"),
            ("QUIT", "221 2.0.0 Bye\r\n"),
        ]);
        let options = MailboxCheckOptions {
            port,
            ..MailboxCheckOptions::default()
        };
        let resolver = make_resolver(MxRecord::new(10, "127.0.0.1"));
        let result =
            check_with_resolver("user@example.com", &options, &resolver).expect("verification");
        match result.status {
            MailboxStatus::Rejected { code, .. } => assert_eq!(code, 550),
            other => panic!("unexpected status: {other:?}"),
        }
        handle.join().expect("server thread");
    }
}
