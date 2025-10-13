use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub enum ValidationMode {
    Strict,
    Relaxed,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub ok: bool,
    pub reasons: Vec<String>,
}

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("invalid format")]
    InvalidFormat,
    #[error("too long")]
    TooLong,
    #[error("{0}")]
    Other(String),
}

pub fn validate_email(email: &str, mode: ValidationMode) -> Result<ValidationReport, EmailError> {
    let input = email.trim(); // on ne modifie pas l'original dans le rapport, juste pour tests

    let mut reasons = Vec::new();

    // longueur totale (RFC 5321: 254 max avec @)
    if input.len() > 254 {
        reasons.push(format!("total length {} > 254", input.len()));
    }

    // doit contenir exactement un '@'
    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        reasons.push("must contain exactly one '@'".to_string());
        return Ok(ValidationReport { ok: false, reasons });
    }
    let (local, domain) = (parts[0], parts[1]);

    // longueur local part
    if local.is_empty() || local.len() > 64 {
        reasons.push(format!(
            "local part length {} invalid (1..=64)",
            local.len()
        ));
    }

    // validation domaine (idna + labels)
    let domain_ascii = match idna::domain_to_ascii(domain) {
        Ok(d) => d,
        Err(_) => {
            reasons.push("domain punycode conversion failed".to_string());
            String::new()
        }
    };
    if !domain_ascii.is_empty() {
        // au moins un point
        if !domain_ascii.contains('.') {
            reasons.push("domain must contain at least one dot".to_string());
        }
        for label in domain_ascii.split('.') {
            if label.is_empty() {
                reasons.push("empty domain label".to_string());
                continue;
            }
            if label.len() > 63 {
                reasons.push(format!(
                    "domain label '{}' length {} > 63",
                    label,
                    label.len()
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                reasons.push(format!(
                    "domain label '{}' cannot start/end with '-'",
                    label
                ));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                reasons.push(format!("domain label '{}' has invalid chars", label));
            }
        }
    }

    // validation local part
    let local_ok = match mode {
        ValidationMode::Strict => is_local_strict(local),
        ValidationMode::Relaxed => is_local_relaxed(local),
    };
    if !local_ok {
        reasons.push(match mode {
            ValidationMode::Strict => "invalid local part (strict rules)".into(),
            ValidationMode::Relaxed => "invalid local part (relaxed rules)".into(),
        });
    }

    let ok = reasons.is_empty();
    Ok(ValidationReport { ok, reasons })
}

fn is_local_strict(s: &str) -> bool {
    // atext ASCII + '.' non initial/terminal, pas de ".."
    if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '/'
                    | '='
                    | '?'
                    | '^'
                    | '_'
                    | '`'
                    | '{'
                    | '|'
                    | '}'
                    | '~'
                    | '.'
            )
    })
}

fn is_local_relaxed(s: &str) -> bool {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        // autorise quoted-string simple en mode relaxed
        true
    } else {
        is_local_strict(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_basic() {
        let r = validate_email("alice@example.com", ValidationMode::Strict).unwrap();
        assert!(r.ok, "{:?}", r.reasons);
    }
    #[test]
    fn rejects_double_at() {
        let r = validate_email("a@@b", ValidationMode::Strict).unwrap();
        assert!(!r.ok);
    }
}
