use anyhow::{Result, bail};

use mailcheck_lib::{Existence, SmtpProbeOptions, check_mailaddress_exists};

#[cfg(feature = "with-serde")]
use serde::Serialize;

pub struct VerifyConfig<'a> {
    pub email: &'a str,
    pub format: &'a str,
    pub helo: Option<&'a str>,
    pub mail_from: Option<&'a str>,
    pub require_starttls: bool,
    pub catchall_probes: u8,
    pub max_mx: usize,
    pub timeout_ms: u64,
    pub ipv6: bool,
}

pub fn run_verify_exists(cfg: VerifyConfig<'_>) -> Result<()> {
    let mut options = SmtpProbeOptions::default();
    if let Some(helo) = cfg.helo {
        options.helo_domain = helo.to_string();
    }
    if let Some(mail) = cfg.mail_from {
        options.mail_from = mail.to_string();
    }
    options.starttls_required = cfg.require_starttls;
    options.catchall_probes = cfg.catchall_probes;
    options.max_mx = cfg.max_mx;
    options.timeout_ms = cfg.timeout_ms;
    options.ipv6 = cfg.ipv6;

    let report = check_mailaddress_exists(cfg.email, &options)?;

    match cfg.format {
        "human" => print_human(&report),
        "json" => {
            #[cfg(feature = "with-serde")]
            {
                let payload = ProbePayload::from(&report);
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            #[cfg(not(feature = "with-serde"))]
            {
                bail!("format=json nécessite la feature 'with-serde'");
            }
        }
        other => bail!("format inconnu '{other}', utilisez human|json"),
    }

    Ok(())
}

fn print_human(report: &mailcheck_lib::SmtpProbeReport) {
    println!(
        "Result: {} (confidence {:.2})",
        match &report.result {
            Existence::Exists => "Exists",
            Existence::DoesNotExist => "DoesNotExist",
            Existence::CatchAll => "CatchAll",
            Existence::Indeterminate(_) => "Indeterminate",
        },
        report.confidence
    );
    if let Existence::Indeterminate(reason) = &report.result {
        println!("Reason: {reason}");
    }
    if !report.mx_tried.is_empty() {
        println!("MX tried: {}", report.mx_tried.join(", "));
    }
    println!("Evidence:");
    for line in &report.transcript {
        println!("  {line}");
    }
}

#[cfg(feature = "with-serde")]
#[derive(Serialize)]
struct ProbePayload<'a> {
    result: &'a Existence,
    confidence: f32,
    mx_tried: &'a [String],
    transcript: &'a [String],
}

#[cfg(feature = "with-serde")]
impl<'a> From<&'a mailcheck_lib::SmtpProbeReport> for ProbePayload<'a> {
    fn from(report: &'a mailcheck_lib::SmtpProbeReport) -> Self {
        Self {
            result: &report.result,
            confidence: report.confidence,
            mx_tried: &report.mx_tried,
            transcript: &report.transcript,
        }
    }
}
