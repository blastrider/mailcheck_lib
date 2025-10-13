#![forbid(unsafe_code)]
//! mailcheck_lib — validation format e-mail (MVP)

pub mod validator;
pub use validator::{
    EmailError,
    NormalizedEmail, // << nouveau
    SpecCharacters,
    SpecClass,
    SpecFinding,
    SpecOptions,
    SpecSegment,
    ValidationMode,
    ValidationReport,
    normalize_email, // << nouveau
    normalize_email_with_spec,
    validate_email,
    validate_email_with_spec,
};
