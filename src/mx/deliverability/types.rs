use std::fmt;

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStage {
    Connect,
    Greeting,
    Ehlo,
    MailFrom,
    Vrfy,
    RcptTo,
    Rset,
    Quit,
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    Vrfy,
    RcptTo,
}

/// A raw SMTP reply, preserving the numeric status code and message text.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    pub code: u16,
    pub message: String,
}

impl SmtpReply {
    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }

    pub fn is_transient_failure(&self) -> bool {
        (400..500).contains(&self.code)
    }

    pub fn is_permanent_failure(&self) -> bool {
        (500..600).contains(&self.code)
    }
}

/// A recorded `SMTP` transcript event used for diagnostics.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpEvent {
    Sent {
        stage: AttemptStage,
        command: String,
    },
    Received {
        stage: AttemptStage,
        reply: SmtpReply,
    },
    Error {
        stage: AttemptStage,
        message: String,
    },
}

/// Outcome of a verification attempt against a single MX host.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    Accepted {
        method: VerificationMethod,
        reply: SmtpReply,
    },
    Rejected {
        method: VerificationMethod,
        reply: SmtpReply,
    },
    TemporaryFailure {
        method: VerificationMethod,
        reply: SmtpReply,
    },
    Unreachable {
        message: String,
    },
    ProtocolError {
        message: String,
    },
    NoVerification {
        message: String,
    },
}

impl AttemptOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn as_reply(&self) -> Option<&SmtpReply> {
        match self {
            Self::Accepted { reply, .. }
            | Self::Rejected { reply, .. }
            | Self::TemporaryFailure { reply, .. } => Some(reply),
            _ => None,
        }
    }
}

/// Detailed report for a single SMTP server interrogation.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAttempt {
    pub exchange: String,
    pub address: Option<String>,
    pub events: Vec<SmtpEvent>,
    pub outcome: AttemptOutcome,
}

impl ServerAttempt {
    pub fn new(exchange: impl Into<String>) -> Self {
        Self {
            exchange: exchange.into(),
            address: None,
            events: Vec::new(),
            outcome: AttemptOutcome::NoVerification {
                message: "verification not attempted".to_string(),
            },
        }
    }
}

/// High-level categorisation of mailbox deliverability after probing.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxStatus {
    Deliverable,
    Rejected { code: u16, message: String },
    TemporaryFailure { code: u16, message: String },
    NoMailServer,
    Unreachable,
    Unverified,
}

impl fmt::Display for MailboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deliverable => f.write_str("deliverable"),
            Self::Rejected { code, message } => {
                write!(f, "rejected ({code} {message})")
            }
            Self::TemporaryFailure { code, message } => {
                write!(f, "temporary failure ({code} {message})")
            }
            Self::NoMailServer => f.write_str("no MX records"),
            Self::Unreachable => f.write_str("all servers unreachable"),
            Self::Unverified => f.write_str("verification inconclusive"),
        }
    }
}

/// Aggregated result of [`check_mailaddress_exists`](crate::mx::check_mailaddress_exists).
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxVerification {
    pub email: String,
    pub ascii_domain: String,
    pub status: MailboxStatus,
    pub attempts: Vec<ServerAttempt>,
}
