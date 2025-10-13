mod domain;
mod local;
mod spec;
mod types;

pub use types::{
    EmailError, NormalizedEmail, SpecCharacters, SpecClass, SpecFinding, SpecOptions, SpecSegment,
    ValidationMode, ValidationReport,
};

use domain::{check_domain, normalize_domain};
use local::{is_local_relaxed, is_local_strict};
use spec::{analyze_spec_characters, join_spec_notes};

pub fn validate_email(email: &str, mode: ValidationMode) -> Result<ValidationReport, EmailError> {
    validate_email_with_spec(email, mode, None)
}

pub fn validate_email_with_spec(
    email: &str,
    mode: ValidationMode,
    spec_options: Option<SpecOptions>,
) -> Result<ValidationReport, EmailError> {
    let input = email.trim();

    let mut reasons = Vec::new();

    if input.len() > 254 {
        reasons.push(format!("total length {} > 254", input.len()));
    }

    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        reasons.push("must contain exactly one '@'".to_string());
        return Ok(ValidationReport {
            ok: false,
            reasons,
            spec_chars: None,
        });
    }
    let (local, domain) = (parts[0], parts[1]);

    let spec_computation = spec_options
        .as_ref()
        .map(|options| analyze_spec_characters(local, domain, options));

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

    if let (Some(options), Some(spec)) = (spec_options.as_ref(), &spec_computation) {
        spec.apply_policy(options, domain, &mut reasons);
    }

    let ok = reasons.is_empty();
    Ok(ValidationReport {
        ok,
        reasons,
        spec_chars: spec_computation.map(|s| s.characters),
    })
}

/// **NOUVEAU** : valide et renvoie une *sortie normalisée*
/// (local, domaine normalisé, domaine ASCII).
pub fn normalize_email(email: &str, mode: ValidationMode) -> Result<NormalizedEmail, EmailError> {
    normalize_email_with_spec(email, mode, None)
}

pub fn normalize_email_with_spec(
    email: &str,
    mode: ValidationMode,
    spec_options: Option<SpecOptions>,
) -> Result<NormalizedEmail, EmailError> {
    let input = email.trim();
    // décomposer tôt (même si invalide) pour normaliser ce qu’on peut
    let mut local = "";
    let mut domain = "";
    if let Some((l, d)) = input.split_once('@') {
        local = l;
        domain = d;
    }

    let report = if let Some(ref opts) = spec_options {
        validate_email_with_spec(email, mode, Some(opts.clone()))?
    } else {
        validate_email(email, mode)?
    };
    let (domain_lower, ascii_domain) = normalize_domain(domain);

    let ValidationReport {
        ok,
        reasons,
        mut spec_chars,
    } = report;

    // si l'analyse spec n'a pas été faite mais options présentes (cas email sans '@'),
    // lance la détection pour l'inclure dans la sortie normalisée.
    if let Some(opts) = spec_options {
        if spec_chars.is_none() && (!local.is_empty() || !domain.is_empty()) {
            let spec = analyze_spec_characters(local, domain, &opts);
            spec_chars = Some(spec.characters);
        }
    }

    let (has_confusables, has_diacritics, has_mixed_scripts, spec_notes, ascii_hint) =
        if let Some(ref spec) = spec_chars {
            (
                Some(spec.has_confusables),
                Some(spec.has_diacritics),
                Some(spec.has_mixed_scripts),
                join_spec_notes(&spec.details),
                spec.normalized_ascii_hint.clone(),
            )
        } else {
            (None, None, None, None, None)
        };

    Ok(NormalizedEmail {
        original: email.to_string(),
        local: local.to_string(),
        domain: domain_lower,
        ascii_domain,
        mode,
        valid: ok,
        reasons,
        spec_chars,
        has_confusables,
        has_diacritics,
        has_mixed_scripts,
        spec_notes,
        ascii_hint,
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

    #[test]
    fn normalized_spec_fields_populated() {
        let n = normalize_email_with_spec(
            "péché@exämple.com",
            ValidationMode::Strict,
            Some(SpecOptions::standard()),
        )
        .unwrap();
        assert_eq!(n.has_diacritics, Some(true));
        assert_eq!(n.has_confusables, Some(false));
        assert!(n.spec_notes.as_ref().expect("notes").contains("Local"));
        assert!(
            n.ascii_hint
                .as_ref()
                .expect("ascii hint")
                .eq("peche@example.com")
        );
    }

    #[test]
    fn strict_profile_flags_confusable_domain() {
        let report = validate_email_with_spec(
            "user@exаmple.com",
            ValidationMode::Strict,
            Some(SpecOptions::strict()),
        )
        .unwrap();
        assert!(!report.ok);
        assert!(report.reasons.iter().any(|r| r.contains("confusable")));
        assert!(report.spec_chars.is_some());
    }

    #[test]
    fn fr_fraud_profile_adds_tld_warning() {
        let report = validate_email_with_spec(
            "user@exаmple.fr",
            ValidationMode::Strict,
            Some(SpecOptions::fr_fraud()),
        )
        .unwrap();
        assert!(!report.ok);
        assert!(report.reasons.iter().any(|r| r.contains(".fr domain")));
    }
}
