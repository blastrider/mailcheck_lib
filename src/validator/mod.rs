//! Validator module: expose l’API et orchestre les sous-modules.

mod domain;
mod local;
mod types;

pub use types::{EmailError, ValidationMode, ValidationReport};

use domain::check_domain;
use local::{is_local_relaxed, is_local_strict};

/// Valide le **format** d’une adresse e-mail (pas de MX/SMTP).
///
/// Retourne un `ValidationReport` détaillant les raisons en cas d’invalidation.
///
/// # Exemples
/// ```
/// use mailcheck_lib::{validate_email, ValidationMode};
/// let r = validate_email("alice@example.com", ValidationMode::Strict).unwrap();
/// assert!(r.ok);
/// ```
pub fn validate_email(email: &str, mode: ValidationMode) -> Result<ValidationReport, EmailError> {
    let input = email.trim(); // on ne modifie pas l’original, juste pour les checks

    let mut reasons = Vec::new();

    // Longueur totale (RFC 5321: 254 max avec le '@')
    if input.len() > 254 {
        reasons.push(format!("total length {} > 254", input.len()));
    }

    // Doit contenir exactement un '@'
    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        reasons.push("must contain exactly one '@'".to_string());
        return Ok(ValidationReport { ok: false, reasons });
    }
    let (local, domain) = (parts[0], parts[1]);

    // Longueur local-part
    if local.is_empty() || local.len() > 64 {
        reasons.push(format!(
            "local part length {} invalid (1..=64)",
            local.len()
        ));
    }

    // Domaine: IDNA + labels
    check_domain(domain, &mut reasons);

    // Local-part selon le mode
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
