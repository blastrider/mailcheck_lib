//! SMTP deliverability probing utilities (`with-smtp-verify` feature).
//!
//! The public entry point is [`check_mailaddress_exists`], which executes a
//! minimal SMTP dialogue against the MX hosts (with A/AAAA fallback) and
//! classifies the observed behaviour into [`Existence`] variants.

mod dns;
mod error;
mod options;
mod probe;
mod session;
mod types;
mod util;

pub use error::SmtpVerifyError;
pub use options::SmtpProbeOptions;
pub use probe::check_mailaddress_exists;
pub use types::{Existence, SmtpProbeReport};
