use mailcheck_lib::{
    AuthError, AuthLookupOptions, AuthStatus, DkimIssue, DkimPolicyStatus, DkimSelectorStatus,
    DkimWeakness, DmarcIssue, DmarcPolicy, DmarcStatus, DmarcWeakness, NormalizedEmail, SpfIssue,
    SpfQualifier, SpfStatus, check_auth_records_with_options,
};

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct AuthSummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub status: Option<AuthStatusSnapshot>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub skipped: Option<String>,
}

impl AuthSummary {
    pub fn from_status(status: AuthStatus) -> Self {
        Self {
            status: Some(AuthStatusSnapshot::from_status(status)),
            error: None,
            skipped: None,
        }
    }

    pub fn from_error(error: &AuthError) -> Self {
        Self {
            status: None,
            error: Some(error.to_string()),
            skipped: None,
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            status: None,
            error: None,
            skipped: Some(reason.into()),
        }
    }

    pub fn human_lines(&self) -> Vec<String> {
        if let Some(error) = &self.error {
            return vec![format!("error: {error}")];
        }
        if let Some(reason) = &self.skipped {
            return vec![format!("skipped: {reason}")];
        }
        let Some(status) = &self.status else {
            return vec!["unknown".to_string()];
        };

        let mut lines = Vec::new();
        lines.push(format!("domain={}", status.domain));
        lines.push(format!("spf={}", status.spf.summary()));
        lines.push(format!("dmarc={}", status.dmarc.summary()));
        lines.push(format!("dkim_policy={}", status.dkim_policy.summary()));

        if status.selectors.is_empty() {
            lines.push("dkim_selectors=none".to_string());
        } else if status.selectors.len() == 1 {
            let selector = &status.selectors[0];
            lines.push(format!(
                "dkim_selector {} {}",
                selector.selector,
                selector.summary()
            ));
        } else {
            lines.push("dkim_selectors:".to_string());
            for selector in &status.selectors {
                lines.push(format!("  {} {}", selector.selector, selector.summary()));
            }
        }

        lines
    }

    #[cfg(feature = "with-csv")]
    pub fn csv_fields(&self) -> AuthCsvFields {
        if let Some(status) = &self.status {
            let selectors = if status.selectors.is_empty() {
                String::new()
            } else {
                status
                    .selectors
                    .iter()
                    .map(|selector| format!("{} {}", selector.selector, selector.summary()))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            AuthCsvFields {
                spf: status.spf.summary(),
                dmarc: status.dmarc.summary(),
                dkim_policy: status.dkim_policy.summary(),
                selectors,
                error: String::new(),
                skipped: String::new(),
            }
        } else {
            AuthCsvFields {
                spf: String::new(),
                dmarc: String::new(),
                dkim_policy: String::new(),
                selectors: String::new(),
                error: self.error.clone().unwrap_or_default(),
                skipped: self.skipped.clone().unwrap_or_default(),
            }
        }
    }
}

#[cfg(all(feature = "with-auth-records", feature = "with-csv"))]
#[derive(Debug, Clone)]
pub struct AuthCsvFields {
    pub spf: String,
    pub dmarc: String,
    pub dkim_policy: String,
    pub selectors: String,
    pub error: String,
    pub skipped: String,
}

#[cfg(all(feature = "with-auth-records", feature = "with-csv"))]
impl AuthCsvFields {
    pub fn empty() -> Self {
        Self {
            spf: String::new(),
            dmarc: String::new(),
            dkim_policy: String::new(),
            selectors: String::new(),
            error: String::new(),
            skipped: String::new(),
        }
    }
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct AuthStatusSnapshot {
    pub domain: String,
    pub spf: AuthSectionSnapshot,
    pub dmarc: AuthSectionSnapshot,
    pub dkim_policy: AuthSectionSnapshot,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub selectors: Vec<AuthSelectorSnapshot>,
}

impl AuthStatusSnapshot {
    fn from_status(status: AuthStatus) -> Self {
        Self {
            domain: status.domain,
            spf: summarize_spf(&status.spf),
            dmarc: summarize_dmarc(&status.dmarc),
            dkim_policy: summarize_dkim_policy(&status.dkim.policy),
            selectors: status
                .dkim
                .selectors
                .into_iter()
                .map(summarize_selector)
                .collect(),
        }
    }
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct AuthSectionSnapshot {
    status: String,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    detail: Option<String>,
}

impl AuthSectionSnapshot {
    fn new(status: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            status: status.into(),
            detail,
        }
    }

    pub fn summary(&self) -> String {
        if let Some(detail) = &self.detail {
            if detail.is_empty() {
                self.status.clone()
            } else {
                format!("{} ({detail})", self.status)
            }
        } else {
            self.status.clone()
        }
    }
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct AuthSelectorSnapshot {
    pub selector: String,
    status: String,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    detail: Option<String>,
}

impl AuthSelectorSnapshot {
    fn new(selector: String, status: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            selector,
            status: status.into(),
            detail,
        }
    }

    pub fn summary(&self) -> String {
        if let Some(detail) = &self.detail {
            if detail.is_empty() {
                self.status.clone()
            } else {
                format!("{} ({detail})", self.status)
            }
        } else {
            self.status.clone()
        }
    }
}

pub fn resolve(row: &NormalizedEmail, skip_dkim_policy: bool, selectors: &[String]) -> AuthSummary {
    let target = if !row.ascii_domain.is_empty() {
        row.ascii_domain.as_str()
    } else {
        row.domain.as_str()
    };
    if target.trim().is_empty() {
        return AuthSummary::skipped("domain missing");
    }

    let mut options = AuthLookupOptions::new();
    if skip_dkim_policy {
        options = options.check_policy_record(false);
    }
    if !selectors.is_empty() {
        options = options.with_dkim_selectors(selectors.iter().cloned());
    }

    match check_auth_records_with_options(target, &options) {
        Ok(status) => AuthSummary::from_status(status),
        Err(AuthError::EmptyDomain) => AuthSummary::skipped("domain missing"),
        Err(err) => AuthSummary::from_error(&err),
    }
}

fn summarize_spf(status: &SpfStatus) -> AuthSectionSnapshot {
    match status {
        SpfStatus::Missing => AuthSectionSnapshot::new("missing", None),
        SpfStatus::MultipleRecords { records } => {
            let detail = if records.is_empty() {
                None
            } else {
                Some(format!("records={}", records.join(" | ")))
            };
            AuthSectionSnapshot::new("multiple_records", detail)
        }
        SpfStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_spf_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
        SpfStatus::Delegated { record, target } => {
            let detail = format!("target={target}; record={record}");
            AuthSectionSnapshot::new("delegated", Some(detail))
        }
        SpfStatus::Weak { record, qualifier } => {
            let detail = format!(
                "qualifier={}; record={record}",
                describe_spf_qualifier(*qualifier)
            );
            AuthSectionSnapshot::new("weak_policy", Some(detail))
        }
        SpfStatus::Compliant { record, qualifier } => {
            let detail = format!(
                "qualifier={}; record={record}",
                describe_spf_qualifier(*qualifier)
            );
            AuthSectionSnapshot::new("compliant", Some(detail))
        }
    }
}

fn summarize_dmarc(status: &DmarcStatus) -> AuthSectionSnapshot {
    match status {
        DmarcStatus::Missing => AuthSectionSnapshot::new("missing", None),
        DmarcStatus::MultipleRecords { records } => {
            let detail = if records.is_empty() {
                None
            } else {
                Some(format!("records={}", records.join(" | ")))
            };
            AuthSectionSnapshot::new("multiple_records", detail)
        }
        DmarcStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_dmarc_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
        DmarcStatus::Weak {
            record,
            policy,
            weakness,
        } => {
            let detail = format!(
                "policy={}; weakness={}; record={record}",
                describe_dmarc_policy(*policy),
                describe_dmarc_weakness(*weakness)
            );
            AuthSectionSnapshot::new("weak_policy", Some(detail))
        }
        DmarcStatus::Compliant { record, policy } => {
            let detail = format!("policy={}; record={record}", describe_dmarc_policy(*policy));
            AuthSectionSnapshot::new("compliant", Some(detail))
        }
    }
}

fn summarize_dkim_policy(status: &DkimPolicyStatus) -> AuthSectionSnapshot {
    match status {
        DkimPolicyStatus::NotRequested => AuthSectionSnapshot::new("not_requested", None),
        DkimPolicyStatus::Missing => AuthSectionSnapshot::new("missing", None),
        DkimPolicyStatus::Present { record, testing } => {
            let detail = format!("testing={testing}; record={record}");
            AuthSectionSnapshot::new("present", Some(detail))
        }
        DkimPolicyStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_dkim_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
    }
}

fn summarize_selector(status: DkimSelectorStatus) -> AuthSelectorSnapshot {
    match status {
        DkimSelectorStatus::Missing { selector } => {
            AuthSelectorSnapshot::new(selector, "missing", None)
        }
        DkimSelectorStatus::Invalid {
            selector,
            records,
            issue,
        } => {
            let detail = if records.is_empty() {
                format!("issue={}", describe_dkim_issue(&issue))
            } else {
                format!(
                    "issue={}; records={}",
                    describe_dkim_issue(&issue),
                    records.join(" | ")
                )
            };
            AuthSelectorSnapshot::new(selector, "invalid", Some(detail))
        }
        DkimSelectorStatus::Weak {
            selector,
            record,
            weakness,
        } => {
            let detail = format!(
                "weakness={}; record={record}",
                describe_dkim_weakness(weakness)
            );
            AuthSelectorSnapshot::new(selector, "weak", Some(detail))
        }
        DkimSelectorStatus::Compliant { selector, record } => {
            let detail = format!("record={record}");
            AuthSelectorSnapshot::new(selector, "compliant", Some(detail))
        }
    }
}

fn describe_spf_issue(issue: &SpfIssue) -> &'static str {
    match issue {
        SpfIssue::InvalidVersion => "invalid_version",
        SpfIssue::MissingAllMechanism => "missing_all_mechanism",
    }
}

fn describe_spf_qualifier(qualifier: SpfQualifier) -> &'static str {
    match qualifier {
        SpfQualifier::Fail => "-all",
        SpfQualifier::SoftFail => "~all",
        SpfQualifier::Neutral => "?all",
        SpfQualifier::Pass => "+all",
    }
}

fn describe_dmarc_issue(issue: &DmarcIssue) -> String {
    match issue {
        DmarcIssue::InvalidVersion => "invalid_version".to_string(),
        DmarcIssue::MissingPolicy => "missing_policy".to_string(),
        DmarcIssue::UnknownPolicy { policy } => format!("unknown_policy({policy})"),
    }
}

fn describe_dmarc_policy(policy: DmarcPolicy) -> &'static str {
    match policy {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    }
}

fn describe_dmarc_weakness(weakness: DmarcWeakness) -> &'static str {
    match weakness {
        DmarcWeakness::MonitoringPolicy => "monitoring_policy",
        DmarcWeakness::QuarantinePolicy => "quarantine_policy",
    }
}

fn describe_dkim_issue(issue: &DkimIssue) -> String {
    match issue {
        DkimIssue::InvalidVersion => "invalid_version".to_string(),
        DkimIssue::MissingPublicKey => "missing_public_key".to_string(),
        DkimIssue::MultipleRecords { count } => format!("multiple_records({count})"),
    }
}

fn describe_dkim_weakness(weakness: DkimWeakness) -> &'static str {
    match weakness {
        DkimWeakness::TestingFlag => "testing_flag",
    }
}
