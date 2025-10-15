use std::borrow::Cow;
use std::time::Duration;

use crate::validator::ValidationMode;

/// Controls how [`check_mailaddress_exists`](crate::mx::check_mailaddress_exists) interrogates
/// SMTP servers.
#[derive(Debug, Clone)]
pub struct MailboxCheckOptions {
    pub port: u16,
    pub validation_mode: ValidationMode,
    pub helo_domain: Option<String>,
    pub envelope_sender: Option<String>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub max_servers: usize,
    pub use_vrfy: bool,
}

impl Default for MailboxCheckOptions {
    fn default() -> Self {
        Self {
            port: 25,
            validation_mode: ValidationMode::Strict,
            helo_domain: None,
            envelope_sender: None,
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
            max_servers: 3,
            use_vrfy: true,
        }
    }
}

impl MailboxCheckOptions {
    /// Returns the hostname used in the `EHLO` command. Defaults to the ASCII domain
    /// of the target mailbox when none is provided.
    pub fn helo_domain<'a>(&'a self, ascii_domain: &'a str) -> Cow<'a, str> {
        self.helo_domain
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Borrowed(ascii_domain))
    }

    /// Returns the envelope sender used in the `MAIL FROM` command. When unspecified
    /// a `postmaster@domain` placeholder is synthesised.
    pub fn envelope_sender(&self, ascii_domain: &str) -> String {
        self.envelope_sender
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("postmaster@{ascii_domain}"))
    }
}
