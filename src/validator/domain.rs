/// Valide le domaine: conversion IDNA + checks de labels.
/// Push des raisons invalidantes dans `reasons`.
pub(crate) fn check_domain(domain: &str, reasons: &mut Vec<String>) {
    let domain_ascii = match idna::domain_to_ascii(domain) {
        Ok(d) => d,
        Err(_) => {
            reasons.push("domain punycode conversion failed".to_string());
            return;
        }
    };

    if domain_ascii.is_empty() {
        reasons.push("domain empty after IDNA conversion".to_string());
        return;
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_domain_ok() {
        let mut reasons = vec![];
        check_domain("example.com", &mut reasons);
        assert!(reasons.is_empty(), "{:?}", reasons);
    }

    #[test]
    fn label_too_long() {
        let long = "a".repeat(64);
        let mut reasons = vec![];
        check_domain(&format!("{}.com", long), &mut reasons);
        assert!(!reasons.is_empty());
    }
}
