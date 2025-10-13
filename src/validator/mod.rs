mod domain;
mod local;
mod types;

pub use types::{EmailError, NormalizedEmail, ValidationMode, ValidationReport};

use domain::{check_domain, normalize_domain};
use local::{is_local_relaxed, is_local_strict};

pub fn validate_email(email: &str, mode: ValidationMode) -> Result<ValidationReport, EmailError> {
    let input = email.trim();

    let mut reasons = Vec::new();

    if input.len() > 254 {
        reasons.push(format!("total length {} > 254", input.len()));
    }

    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        reasons.push("must contain exactly one '@'".to_string());
        return Ok(ValidationReport { ok: false, reasons });
    }
    let (local, domain) = (parts[0], parts[1]);

    if local.is_empty() || local.len() > 64 {
        reasons.push(format!(
            "local part length {} invalid (1..=64)",
            local.len()
        ));
    }

    check_domain(domain, &mut reasons);

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

/// **NOUVEAU** : valide et renvoie une *sortie normalisée*
/// (local, domaine normalisé, domaine ASCII).
pub fn normalize_email(email: &str, mode: ValidationMode) -> Result<NormalizedEmail, EmailError> {
    let input = email.trim();
    // décomposer tôt (même si invalide) pour normaliser ce qu’on peut
    let mut local = "";
    let mut domain = "";
    if let Some((l, d)) = input.split_once('@') {
        local = l;
        domain = d;
    }

    let report = validate_email(email, mode)?;
    let (domain_lower, ascii_domain) = normalize_domain(domain);

    Ok(NormalizedEmail {
        original: email.to_string(),
        local: local.to_string(),
        domain: domain_lower,
        ascii_domain,
        mode,
        valid: report.ok,
        reasons: report.reasons,
    })
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
    fn normalized_has_ascii_domain() {
        let n = normalize_email("alice@exämple.com", ValidationMode::Strict).unwrap();
        assert!(!n.ascii_domain.is_empty());
    }
}
