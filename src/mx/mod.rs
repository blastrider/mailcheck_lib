//! DNS MX resolution helpers (optional `with-mx` feature).
//!
//! The public entry point is [`check_mx`], which performs a synchronous lookup
//! using the system resolver and returns a [`MxStatus`] describing the outcome.

mod error;
mod resolver;
mod types;

pub use error::MxError as Error;
pub use resolver::check_mx;
pub use types::{MxRecord, MxStatus};

#[cfg(test)]
mod tests;
