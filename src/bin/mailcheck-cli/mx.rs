use mailcheck_lib::{MxError, MxStatus, NormalizedEmail, check_mx};

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct MxSummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub status: Option<MxStatus>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub skipped: Option<String>,
}

impl MxSummary {
    pub fn from_status(status: MxStatus) -> Self {
        Self {
            status: Some(status),
            error: None,
            skipped: None,
        }
    }

    pub fn from_error(error: &MxError) -> Self {
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

    pub fn human_summary(&self) -> String {
        if let Some(status) = &self.status {
            match status {
                MxStatus::Records(records) => {
                    if records.is_empty() {
                        "records: <empty>".to_string()
                    } else {
                        let summary = records
                            .iter()
                            .map(|r| format!("{}:{}", r.preference, r.exchange))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("records: {summary}")
                    }
                }
                MxStatus::NoRecords => "no MX records".to_string(),
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
        if let Some(status) = &self.status {
            match status {
                MxStatus::Records(records) => {
                    let detail = records
                        .iter()
                        .map(|r| format!("{}:{}", r.preference, r.exchange))
                        .collect::<Vec<_>>()
                        .join(";");
                    ("records".to_string(), detail)
                }
                MxStatus::NoRecords => ("no_records".to_string(), String::new()),
            }
        } else if let Some(error) = &self.error {
            ("error".to_string(), error.clone())
        } else if let Some(reason) = &self.skipped {
            ("skipped".to_string(), reason.clone())
        } else {
            ("unknown".to_string(), String::new())
        }
    }
}

pub fn resolve(row: &NormalizedEmail) -> MxSummary {
    let target = if !row.ascii_domain.is_empty() {
        row.ascii_domain.as_str()
    } else {
        row.domain.as_str()
    };

    if target.trim().is_empty() {
        return MxSummary::skipped("domain missing");
    }

    match check_mx(target) {
        Ok(status) => MxSummary::from_status(status),
        Err(MxError::EmptyDomain) => MxSummary::skipped("domain missing"),
        Err(err) => MxSummary::from_error(&err),
    }
}
