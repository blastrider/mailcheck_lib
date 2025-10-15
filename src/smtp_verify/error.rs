use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmtpVerifyError {
    #[error("invalid email address: {reasons:?}")]
    InvalidEmail { reasons: Vec<String> },
    #[error("domain normalisation failed: {0}")]
    Idna(String),
    #[error("resolver initialization failed: {source}")]
    ResolverInit {
        #[source]
        source: std::io::Error,
    },
    #[error("DNS lookup failed: {source}")]
    Lookup {
        #[source]
        source: trust_dns_resolver::error::ResolveError,
    },
    #[error("no SMTP servers available for the domain")]
    NoSmtpServers,
    #[error("connection to {host} failed: {source}")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
    #[error("TLS handshake failed: {source}")]
    Tls {
        #[source]
        source: native_tls::Error,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("STARTTLS required but not advertised by {host}")]
    StartTlsUnavailable { host: String },
}

impl SmtpVerifyError {
    pub fn invalid_email(reasons: Vec<String>) -> Self {
        Self::InvalidEmail { reasons }
    }

    pub fn idna<T: std::fmt::Display>(err: T) -> Self {
        Self::Idna(err.to_string())
    }
}
