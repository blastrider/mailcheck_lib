use mailcheck_lib::{
    Existence, NormalizedEmail, SmtpProbeOptions, SmtpProbeReport, SmtpVerifyError,
    check_mailaddress_exists,
};

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct DeliverabilitySummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub report: Option<SmtpProbeReport>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub skipped: Option<String>,
}

impl DeliverabilitySummary {
    pub fn from_report(report: SmtpProbeReport) -> Self {
        Self {
            report: Some(report),
            error: None,
            skipped: None,
        }
    }

    pub fn from_error(error: SmtpVerifyError) -> Self {
        Self {
            report: None,
            error: Some(error.to_string()),
            skipped: None,
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            report: None,
            error: None,
            skipped: Some(reason.into()),
        }
    }

    pub fn human_summary(&self) -> String {
        if let Some(report) = &self.report {
            match &report.result {
                Existence::Exists => format!("Exists ({:.2})", report.confidence),
                Existence::DoesNotExist => format!(
                    "DoesNotExist ({:.2}) — {}",
                    report.confidence,
                    first_evidence(report)
                ),
                Existence::CatchAll => format!("CatchAll ({:.2})", report.confidence),
                Existence::Indeterminate(reason) => {
                    format!("Indeterminate ({:.2}) — {reason}", report.confidence)
                }
            }
        } else if let Some(error) = &self.error {
            format!("error: {error}")
        } else if let Some(reason) = &self.skipped {
            format!("skipped: {reason}")
        } else {
            "unknown".to_string()
        }
    }

    #[cfg(feature = "with-csv")]
    pub fn csv_fields(&self) -> (String, String) {
        if let Some(report) = &self.report {
            let status = match &report.result {
                Existence::Exists => "exists",
                Existence::DoesNotExist => "does_not_exist",
                Existence::CatchAll => "catch_all",
                Existence::Indeterminate(_) => "indeterminate",
            };
            let detail = format!("{:.2}|{}", report.confidence, first_evidence(report));
            (status.to_string(), detail)
        } else if let Some(error) = &self.error {
            ("error".to_string(), error.clone())
        } else if let Some(reason) = &self.skipped {
            ("skipped".to_string(), reason.clone())
        } else {
            ("unknown".to_string(), String::new())
        }
    }
}

pub fn probe(row: &NormalizedEmail) -> DeliverabilitySummary {
    probe_with(row, check_mailaddress_exists)
}

fn probe_with<F>(row: &NormalizedEmail, check: F) -> DeliverabilitySummary
where
    F: Fn(&str, &SmtpProbeOptions) -> Result<SmtpProbeReport, SmtpVerifyError>,
{
    if !row.valid {
        return DeliverabilitySummary::skipped("email invalid");
    }
    if row.local.trim().is_empty() {
        return DeliverabilitySummary::skipped("local part missing");
    }

    let domain = if !row.ascii_domain.is_empty() {
        row.ascii_domain.as_str()
    } else if !row.domain.is_empty() {
        row.domain.as_str()
    } else {
        ""
    };

    if domain.is_empty() {
        return DeliverabilitySummary::skipped("domain missing");
    }

    let candidate = format!("{}@{}", row.local, domain);
    let options = SmtpProbeOptions {
        helo_domain: domain.to_string(),
        mail_from: format!("postmaster@{domain}"),
        catchall_probes: 1,
        max_mx: 3,
        ..SmtpProbeOptions::default()
    };

    match check(&candidate, &options) {
        Ok(report) => DeliverabilitySummary::from_report(report),
        Err(error) => DeliverabilitySummary::from_error(error),
    }
}

fn first_evidence(report: &SmtpProbeReport) -> String {
    report
        .transcript
        .iter()
        .find(|line| line.contains("550") || line.contains("250") || line.contains("5.1.1"))
        .cloned()
        .unwrap_or_else(|| report.transcript.first().cloned().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_report(existence: Existence) -> SmtpProbeReport {
        SmtpProbeReport {
            result: existence,
            mx_tried: vec!["mx.example".to_string()],
            transcript: vec!["[mx.example] S: 550 5.1.1 user unknown".to_string()],
            confidence: 0.95,
        }
    }

    #[test]
    fn skips_when_invalid() {
        let normalized = NormalizedEmail {
            original: "bad".to_string(),
            local: String::new(),
            domain: String::new(),
            ascii_domain: String::new(),
            mode: mailcheck_lib::ValidationMode::Strict,
            valid: false,
            reasons: vec!["invalid".to_string()],
            spec_chars: None,
            has_confusables: None,
            has_diacritics: None,
            has_mixed_scripts: None,
            spec_notes: None,
            ascii_hint: None,
        };
        let summary = probe_with(&normalized, |_, _| Ok(fake_report(Existence::Exists)));
        assert_eq!(summary.human_summary(), "skipped: email invalid");
    }

    #[test]
    fn reports_error() {
        let normalized = NormalizedEmail {
            original: "user@example.com".to_string(),
            local: "user".to_string(),
            domain: "example.com".to_string(),
            ascii_domain: "example.com".to_string(),
            mode: mailcheck_lib::ValidationMode::Strict,
            valid: true,
            reasons: Vec::new(),
            spec_chars: None,
            has_confusables: None,
            has_diacritics: None,
            has_mixed_scripts: None,
            spec_notes: None,
            ascii_hint: None,
        };
        let summary = probe_with(&normalized, |_, _| Err(SmtpVerifyError::NoSmtpServers));
        assert!(summary.human_summary().starts_with("error:"));
    }

    #[test]
    fn reports_exists() {
        let normalized = NormalizedEmail {
            original: "user@example.com".to_string(),
            local: "user".to_string(),
            domain: "example.com".to_string(),
            ascii_domain: "example.com".to_string(),
            mode: mailcheck_lib::ValidationMode::Strict,
            valid: true,
            reasons: Vec::new(),
            spec_chars: None,
            has_confusables: None,
            has_diacritics: None,
            has_mixed_scripts: None,
            spec_notes: None,
            ascii_hint: None,
        };
        let summary = probe_with(&normalized, |_, _| Ok(fake_report(Existence::Exists)));
        assert!(summary.human_summary().starts_with("Exists"));
    }
}
