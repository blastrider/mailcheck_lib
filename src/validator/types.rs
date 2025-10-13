use thiserror::Error;

/// Mode de validation
#[derive(Debug, Clone, Copy)]
pub enum ValidationMode {
    Strict,
    Relaxed,
}

/// Rapport de validation (JSON activable via feature `with-serde`)
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub ok: bool,
    pub reasons: Vec<String>,
}

/// Erreurs “fatales” (ex: parse impossible) —
/// l’invalidation “normale” passe par `ValidationReport.ok = false`.
#[derive(Error, Debug)]
pub enum EmailError {
    #[error("invalid format")]
    InvalidFormat,
    #[error("too long")]
    TooLong,
    #[error("{0}")]
    Other(String),
}
