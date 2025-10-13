use thiserror::Error;

// AJOUTE ces derives sur ValidationMode
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Strict,
    Relaxed,
}

// (le reste inchangé)
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub ok: bool,
    pub reasons: Vec<String>,
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
