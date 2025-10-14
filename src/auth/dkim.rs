#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimStatus {
    pub policy: DkimPolicyStatus,
    pub selectors: Vec<DkimSelectorStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimPolicyStatus {
    NotRequested,
    Missing,
    Present { record: String, testing: bool },
    Invalid { record: String, issue: DkimIssue },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimSelectorStatus {
    Missing {
        selector: String,
    },
    Invalid {
        selector: String,
        records: Vec<String>,
        issue: DkimIssue,
    },
    Weak {
        selector: String,
        record: String,
        weakness: DkimWeakness,
    },
    Compliant {
        selector: String,
        record: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimWeakness {
    TestingFlag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimIssue {
    InvalidVersion,
    MissingPublicKey,
    MultipleRecords { count: usize },
}

pub(crate) fn assemble_status(
    policy: DkimPolicyStatus,
    selectors: Vec<DkimSelectorStatus>,
) -> DkimStatus {
    DkimStatus { policy, selectors }
}

pub(crate) fn policy_not_requested() -> DkimPolicyStatus {
    DkimPolicyStatus::NotRequested
}

pub(crate) fn policy_status(records: &[String]) -> DkimPolicyStatus {
    if records.is_empty() {
        return DkimPolicyStatus::Missing;
    }

    let sanitized: Vec<String> = records
        .iter()
        .map(|record| record.trim().to_string())
        .collect();
    let mut relevant = Vec::new();
    for record in sanitized.iter() {
        let parsed = parse_tags(record);
        if parsed
            .version
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("dkim1"))
            .unwrap_or(false)
        {
            relevant.push((record.clone(), parsed));
        }
    }

    if relevant.is_empty() {
        let fallback = sanitized.into_iter().next().unwrap_or_default();
        return DkimPolicyStatus::Invalid {
            record: fallback,
            issue: DkimIssue::InvalidVersion,
        };
    }

    if relevant.len() > 1 {
        let (record, _) = &relevant[0];
        return DkimPolicyStatus::Invalid {
            record: record.clone(),
            issue: DkimIssue::MultipleRecords {
                count: relevant.len(),
            },
        };
    }

    let (record, parsed) = relevant
        .into_iter()
        .next()
        .expect("one record after length check");
    DkimPolicyStatus::Present {
        record,
        testing: parsed.testing,
    }
}

pub(crate) fn selector_status(selector: &str, records: &[String]) -> DkimSelectorStatus {
    if records.is_empty() {
        return DkimSelectorStatus::Missing {
            selector: selector.to_string(),
        };
    }

    let sanitized: Vec<String> = records
        .iter()
        .map(|record| record.trim().to_string())
        .collect();
    let mut relevant = Vec::new();
    for record in sanitized.iter() {
        let parsed = parse_tags(record);
        if parsed
            .version
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("dkim1"))
            .unwrap_or(false)
        {
            relevant.push((record.clone(), parsed));
        }
    }

    if relevant.is_empty() {
        return DkimSelectorStatus::Invalid {
            selector: selector.to_string(),
            records: sanitized,
            issue: DkimIssue::InvalidVersion,
        };
    }

    if relevant.len() > 1 {
        return DkimSelectorStatus::Invalid {
            selector: selector.to_string(),
            records: sanitized,
            issue: DkimIssue::MultipleRecords {
                count: relevant.len(),
            },
        };
    }

    let (record, parsed) = relevant
        .into_iter()
        .next()
        .expect("one record after length check");
    let public_key = parsed.public_key.unwrap_or_default();
    if public_key.is_empty() {
        return DkimSelectorStatus::Invalid {
            selector: selector.to_string(),
            records: sanitized,
            issue: DkimIssue::MissingPublicKey,
        };
    }

    if parsed.testing {
        DkimSelectorStatus::Weak {
            selector: selector.to_string(),
            record,
            weakness: DkimWeakness::TestingFlag,
        }
    } else {
        DkimSelectorStatus::Compliant {
            selector: selector.to_string(),
            record,
        }
    }
}

#[derive(Debug)]
struct ParsedTags {
    version: Option<String>,
    public_key: Option<String>,
    testing: bool,
}

fn parse_tags(record: &str) -> ParsedTags {
    let mut version = None;
    let mut public_key = None;
    let mut testing = false;

    for part in record.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut pieces = trimmed.splitn(2, '=');
        let key = pieces.next().unwrap().trim().to_ascii_lowercase();
        let value = pieces.next().map(str::trim).unwrap_or("").to_string();

        if key == "v" {
            version = Some(value.clone());
        } else if key == "p" {
            public_key = Some(value.clone());
        } else if key == "t" {
            testing = value
                .split(',')
                .any(|flag| flag.trim().eq_ignore_ascii_case("y"));
        }
    }

    ParsedTags {
        version,
        public_key,
        testing,
    }
}
