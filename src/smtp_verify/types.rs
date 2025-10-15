use std::fmt;

#[cfg(feature = "with-serde")]
use serde::{Deserialize, Serialize};

/// Classification of the observed SMTP behaviour for a mailbox.
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existence {
    /// The target address was explicitly accepted while randomly generated
    /// aliases were rejected.
    Exists,
    /// The target address was rejected with a definitive SMTP status code.
    DoesNotExist,
    /// The SMTP server appears to accept any address (catch-all behaviour).
    CatchAll,
    /// The verification could not be concluded. The accompanying string holds
    /// a human-readable reason (temporary failures, timeouts, policies, etc.).
    Indeterminate(String),
}

impl Existence {
    pub fn is_conclusive(&self) -> bool {
        matches!(self, Self::Exists | Self::DoesNotExist)
    }
}

impl fmt::Display for Existence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("Exists"),
            Self::DoesNotExist => f.write_str("DoesNotExist"),
            Self::CatchAll => f.write_str("CatchAll"),
            Self::Indeterminate(reason) => write!(f, "Indeterminate ({reason})"),
        }
    }
}

/// Final report produced by [`check_mailaddress_exists`].
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpProbeReport {
    pub result: Existence,
    pub mx_tried: Vec<String>,
    pub transcript: Vec<String>,
    pub confidence: f32,
}

impl SmtpProbeReport {
    pub fn new(
        result: Existence,
        mx_tried: Vec<String>,
        transcript: Vec<String>,
        confidence: f32,
    ) -> Self {
        Self {
            result,
            mx_tried,
            transcript,
            confidence,
        }
    }
}
