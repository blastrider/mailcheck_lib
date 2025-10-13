#![forbid(unsafe_code)]
//! mailcheck_lib — validation format e-mail (MVP)

pub mod validator;
pub use validator::{EmailError, ValidationMode, ValidationReport, validate_email};
