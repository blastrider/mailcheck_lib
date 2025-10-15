use std::borrow::Cow;
use std::time::Duration;

#[cfg(feature = "with-serde")]
use serde::{Deserialize, Serialize};

/// Configuration knobs for [`check_mailaddress_exists`].
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpProbeOptions {
    pub helo_domain: String,
    pub mail_from: String,
    pub starttls_required: bool,
    pub timeout_ms: u64,
    pub max_mx: usize,
    pub catchall_probes: u8,
    pub ipv6: bool,
}

impl Default for SmtpProbeOptions {
    fn default() -> Self {
        Self {
            helo_domain: "localhost".to_string(),
            mail_from: String::new(),
            starttls_required: false,
            timeout_ms: 5_000,
            max_mx: 3,
            catchall_probes: 1,
            ipv6: false,
        }
    }
}

impl SmtpProbeOptions {
    /// Return the timeout as a [`Duration`]. A zero timeout disables the
    /// connection/read deadline.
    pub fn timeout(&self) -> Option<Duration> {
        if self.timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.timeout_ms))
        }
    }

    pub fn helo_name<'a>(&'a self, fallback: &'a str) -> Cow<'a, str> {
        if self.helo_domain.trim().is_empty() {
            Cow::Borrowed(fallback)
        } else {
            Cow::Borrowed(self.helo_domain.as_str())
        }
    }

    pub fn mail_from<'a>(&'a self, fallback: &'a str) -> Cow<'a, str> {
        if self.mail_from.is_empty() {
            Cow::Borrowed(fallback)
        } else {
            Cow::Owned(self.mail_from.clone())
        }
    }
}
