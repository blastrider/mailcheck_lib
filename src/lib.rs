#![forbid(unsafe_code)]
//! mailcheck_lib — validation format e-mail (MVP)

pub mod validator;
pub use validator::{
    EmailError,
    NormalizedEmail, // << nouveau
    ValidationMode,
    ValidationReport,
    normalize_email, // << nouveau
    validate_email,
};
