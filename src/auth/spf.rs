#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfStatus {
    Missing,
    MultipleRecords {
        records: Vec<String>,
    },
    Invalid {
        record: String,
        issue: SpfIssue,
    },
    Delegated {
        record: String,
        target: String,
    },
    Weak {
        record: String,
        qualifier: SpfQualifier,
    },
    Compliant {
        record: String,
        qualifier: SpfQualifier,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfIssue {
    InvalidVersion,
    MissingAllMechanism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfQualifier {
    Fail,
    SoftFail,
    Neutral,
    Pass,
}

pub(crate) fn evaluate(records: &[String]) -> SpfStatus {
    let mut spf_records: Vec<String> = records
        .iter()
        .map(|record| record.trim())
        .filter(|trimmed| starts_with_ignore_ascii_case(trimmed, "v=spf1"))
        .map(|trimmed| trimmed.to_string())
        .collect();

    if spf_records.is_empty() {
        return SpfStatus::Missing;
    }

    if spf_records.len() > 1 {
        spf_records.sort();
        spf_records.dedup();
        return SpfStatus::MultipleRecords {
            records: spf_records,
        };
    }

    let record = spf_records.remove(0);
    let mut segments = record.split_whitespace();
    let Some(version) = segments.next() else {
        return SpfStatus::Invalid {
            record,
            issue: SpfIssue::InvalidVersion,
        };
    };
    if !version.eq_ignore_ascii_case("v=spf1") {
        return SpfStatus::Invalid {
            record,
            issue: SpfIssue::InvalidVersion,
        };
    }

    let mut qualifier = None;
    let mut redirect = None;

    for token in segments {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if qualifier.is_none() {
            qualifier = qualifier_from_token(&lower);
        }
        if redirect.is_none() && lower.starts_with("redirect=") {
            let target = trimmed
                .split_once('=')
                .map(|(_, value)| value.trim())
                .filter(|value| !value.is_empty());
            if let Some(target) = target {
                redirect = Some(target.to_string());
            }
        }
    }

    if let Some(qualifier) = qualifier {
        match qualifier {
            SpfQualifier::Fail | SpfQualifier::SoftFail => {
                SpfStatus::Compliant { record, qualifier }
            }
            SpfQualifier::Neutral | SpfQualifier::Pass => SpfStatus::Weak { record, qualifier },
        }
    } else if let Some(target) = redirect {
        SpfStatus::Delegated { record, target }
    } else {
        SpfStatus::Invalid {
            record,
            issue: SpfIssue::MissingAllMechanism,
        }
    }
}

fn starts_with_ignore_ascii_case(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .map(|head| head.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn qualifier_from_token(token: &str) -> Option<SpfQualifier> {
    match token {
        "-all" => Some(SpfQualifier::Fail),
        "~all" => Some(SpfQualifier::SoftFail),
        "?all" => Some(SpfQualifier::Neutral),
        "all" | "+all" => Some(SpfQualifier::Pass),
        _ => None,
    }
}
