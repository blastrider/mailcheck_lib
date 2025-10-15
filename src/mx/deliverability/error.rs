use thiserror::Error;

use crate::validator::EmailError;

use super::super::Error as MxError;

/// Errors that can occur while probing SMTP deliverability for a mailbox.
#[derive(Debug, Error)]
pub enum DeliverabilityError {
    #[error("email normalization failed: {source}")]
    EmailNormalization {
        #[source]
        source: EmailError,
    },
    #[error("invalid email address")]
    InvalidEmail { reasons: Vec<String> },
    #[error(transparent)]
    Mx(#[from] MxError),
}

impl DeliverabilityError {
    pub(crate) fn invalid_email(reasons: Vec<String>) -> Self {
        Self::InvalidEmail { reasons }
    }
}
