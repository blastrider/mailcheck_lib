use thiserror::Error;

// AJOUTE ces derives sur ValidationMode
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Strict,
    Relaxed,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecSegment {
    Local,
    Domain,
    Label(String),
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecClass {
    Diacritic,
    Confusable,
    MixedScript,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFinding {
    pub segment: SpecSegment,
    pub codepoint: char,
    pub class: SpecClass,
    pub note: String,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpecCharacters {
    pub has_confusables: bool,
    pub has_diacritics: bool,
    pub has_mixed_scripts: bool,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub details: Vec<SpecFinding>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub normalized_ascii_hint: Option<String>,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub ok: bool,
    pub reasons: Vec<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub spec_chars: Option<SpecCharacters>,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEmail {
    pub original: String,
    pub local: String,
    pub domain: String,
    pub ascii_domain: String,
    pub mode: ValidationMode, // -> a maintenant PartialEq/Eq + (de)serde
    pub valid: bool,
    pub reasons: Vec<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub spec_chars: Option<SpecCharacters>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub has_confusables: Option<bool>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub has_diacritics: Option<bool>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub has_mixed_scripts: Option<bool>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub spec_notes: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ascii_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SpecOptions {
    pub detect_diacritics: bool,
    pub detect_confusables: bool,
    pub detect_mixed_scripts: bool,
    pub ascii_hint: bool,
    pub allowlist_labels: Vec<String>,
    pub domain_confusable_reason: Option<String>,
    pub domain_mixed_scripts_reason: Option<String>,
    pub confusable_tld_warnings: Vec<(String, String)>,
    pub use_fr_hint_extensions: bool,
}

impl Default for SpecOptions {
    fn default() -> Self {
        Self {
            detect_diacritics: true,
            detect_confusables: true,
            detect_mixed_scripts: true,
            ascii_hint: true,
            allowlist_labels: Vec::new(),
            domain_confusable_reason: None,
            domain_mixed_scripts_reason: None,
            confusable_tld_warnings: Vec::new(),
            use_fr_hint_extensions: false,
        }
    }
}

impl SpecOptions {
    pub fn standard() -> Self {
        Self::default()
    }

    pub fn strict() -> Self {
        let mut opts = Self::standard();
        opts.domain_confusable_reason = Some("domain label has confusable non-latin".to_string());
        opts
    }

    pub fn fr_fraud() -> Self {
        let mut opts = Self::standard();
        opts.use_fr_hint_extensions = true;
        opts.domain_confusable_reason =
            Some("fr-fraud profile: domain label has confusable non-latin characters".to_string());
        opts.domain_mixed_scripts_reason =
            Some("fr-fraud profile: domain uses mixed Unicode scripts".to_string());
        opts.confusable_tld_warnings = vec![
            (
                "fr".to_string(),
                "fr-fraud profile: .fr domain with confusable characters detected".to_string(),
            ),
            (
                "gouv.fr".to_string(),
                "fr-fraud profile: .gouv.fr domain with confusable characters detected".to_string(),
            ),
        ];
        opts
    }
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
