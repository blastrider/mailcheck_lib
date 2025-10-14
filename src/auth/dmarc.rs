use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcStatus {
    Missing,
    MultipleRecords {
        records: Vec<String>,
    },
    Invalid {
        record: String,
        issue: DmarcIssue,
    },
    Weak {
        record: String,
        policy: DmarcPolicy,
        weakness: DmarcWeakness,
    },
    Compliant {
        record: String,
        policy: DmarcPolicy,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcIssue {
    InvalidVersion,
    MissingPolicy,
    UnknownPolicy { policy: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcWeakness {
    MonitoringPolicy,
    QuarantinePolicy,
}

pub(crate) fn evaluate(records: &[String]) -> DmarcStatus {
    let mut dmarc_records: Vec<String> = records
        .iter()
        .map(|record| record.trim())
        .filter(|trimmed| starts_with_ignore_ascii_case(trimmed, "v=dmarc1"))
        .map(|trimmed| trimmed.to_string())
        .collect();

    if dmarc_records.is_empty() {
        return DmarcStatus::Missing;
    }

    if dmarc_records.len() > 1 {
        dmarc_records.sort();
        dmarc_records.dedup();
        return DmarcStatus::MultipleRecords {
            records: dmarc_records,
        };
    }

    let record = dmarc_records.remove(0);
    let tags = parse_tags(&record);

    let Some(version) = tags.get("v") else {
        return DmarcStatus::Invalid {
            record,
            issue: DmarcIssue::InvalidVersion,
        };
    };
    if !version.eq_ignore_ascii_case("dmarc1") {
        return DmarcStatus::Invalid {
            record,
            issue: DmarcIssue::InvalidVersion,
        };
    }

    let Some(policy) = tags.get("p") else {
        return DmarcStatus::Invalid {
            record,
            issue: DmarcIssue::MissingPolicy,
        };
    };

    match policy.to_ascii_lowercase().as_str() {
        "reject" => DmarcStatus::Compliant {
            record,
            policy: DmarcPolicy::Reject,
        },
        "quarantine" => DmarcStatus::Weak {
            record,
            policy: DmarcPolicy::Quarantine,
            weakness: DmarcWeakness::QuarantinePolicy,
        },
        "none" => DmarcStatus::Weak {
            record,
            policy: DmarcPolicy::None,
            weakness: DmarcWeakness::MonitoringPolicy,
        },
        other => DmarcStatus::Invalid {
            record,
            issue: DmarcIssue::UnknownPolicy {
                policy: other.to_string(),
            },
        },
    }
}

fn starts_with_ignore_ascii_case(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .map(|head| head.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn parse_tags(record: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for part in record.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut kv = trimmed.splitn(2, '=');
        let key = kv.next().unwrap().trim().to_ascii_lowercase();
        let value = kv.next().map(str::trim).unwrap_or("").to_string();
        tags.insert(key, value);
    }
    tags
}
