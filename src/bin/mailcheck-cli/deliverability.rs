use mailcheck_lib::{
    DeliverabilityError, MailboxStatus, MailboxVerification, NormalizedEmail,
    check_mailaddress_exists,
};

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct DeliverabilitySummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub verification: Option<MailboxVerification>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub skipped: Option<String>,
}

impl DeliverabilitySummary {
    pub fn from_verification(verification: MailboxVerification) -> Self {
        Self {
            verification: Some(verification),
            error: None,
            skipped: None,
        }
    }

    pub fn from_error(error: DeliverabilityError) -> Self {
        match error {
            DeliverabilityError::InvalidEmail { reasons } => {
                Self::skipped(format!("invalid email: {}", reasons.join(", ")))
            }
            other => Self {
                verification: None,
                error: Some(other.to_string()),
                skipped: None,
            },
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            verification: None,
            error: None,
            skipped: Some(reason.into()),
        }
    }

    pub fn human_summary(&self) -> String {
        if let Some(verification) = &self.verification {
            human_for_status(&verification.status)
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
        if let Some(verification) = &self.verification {
            csv_for_status(&verification.status)
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
    F: Fn(&str) -> Result<MailboxVerification, DeliverabilityError>,
{
    if !row.valid {
        return DeliverabilitySummary::skipped("email invalid");
    }
    if row.local.is_empty() {
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
    match check(&candidate) {
        Ok(verification) => DeliverabilitySummary::from_verification(verification),
        Err(error) => DeliverabilitySummary::from_error(error),
    }
}

fn human_for_status(status: &MailboxStatus) -> String {
    match status {
        MailboxStatus::Deliverable => "deliverable".to_string(),
        MailboxStatus::Rejected { code, message } => {
            format!("rejected {code}: {message}")
        }
        MailboxStatus::TemporaryFailure { code, message } => {
            format!("temporary failure {code}: {message}")
        }
        MailboxStatus::NoMailServer => "no MX records".to_string(),
        MailboxStatus::Unreachable => "all servers unreachable".to_string(),
        MailboxStatus::Unverified => "verification inconclusive".to_string(),
    }
}

#[cfg(feature = "with-csv")]
fn csv_for_status(status: &MailboxStatus) -> (String, String) {
    match status {
        MailboxStatus::Deliverable => ("deliverable".to_string(), String::new()),
        MailboxStatus::Rejected { code, message } => {
            ("rejected".to_string(), format!("{code}:{message}"))
        }
        MailboxStatus::TemporaryFailure { code, message } => {
            ("temporary_failure".to_string(), format!("{code}:{message}"))
        }
        MailboxStatus::NoMailServer => ("no_mx".to_string(), String::new()),
        MailboxStatus::Unreachable => ("unreachable".to_string(), String::new()),
        MailboxStatus::Unverified => ("unverified".to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deliverable(email: &str) -> MailboxVerification {
        MailboxVerification {
            email: email.to_string(),
            ascii_domain: "example.com".to_string(),
            status: MailboxStatus::Deliverable,
            attempts: Vec::new(),
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
        let summary = probe_with(&normalized, |_| Ok(deliverable("bad")));
        assert_eq!(
            summary.human_summary(),
            "skipped: email invalid".to_string()
        );
    }

    #[test]
    fn reports_deliverable() {
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
        let summary = probe_with(&normalized, |_| Ok(deliverable("user@example.com")));
        assert_eq!(summary.human_summary(), "deliverable");
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
        let summary = probe_with(&normalized, |_| {
            Err(DeliverabilityError::InvalidEmail {
                reasons: vec!["oops".to_string()],
            })
        });
        assert!(
            summary.human_summary().contains("invalid email"),
            "expected invalid email, got {}",
            summary.human_summary()
        );
    }
}
