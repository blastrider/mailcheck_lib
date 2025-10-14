use thiserror::Error;

/// Errors raised when checking DNS authentication records.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("domain is empty")]
    EmptyDomain,
    #[error("domain IDNA conversion failed")]
    IdnaConversion {
        #[source]
        source: idna::Errors,
    },
    #[error("resolver initialization failed: {source}")]
    ResolverInit {
        #[source]
        source: std::io::Error,
    },
    #[error("TXT lookup failed for {name}: {source}")]
    TxtLookup {
        name: String,
        #[source]
        source: trust_dns_resolver::error::ResolveError,
    },
    #[error("TXT record {name} contains invalid UTF-8 data: {source}")]
    TxtDataUtf8 {
        name: String,
        #[source]
        source: std::str::Utf8Error,
    },
}

impl AuthError {
    pub(crate) fn idna(source: idna::Errors) -> Self {
        Self::IdnaConversion { source }
    }

    pub(crate) fn resolver_init(source: std::io::Error) -> Self {
        Self::ResolverInit { source }
    }

    pub(crate) fn txt_lookup(
        name: impl Into<String>,
        source: trust_dns_resolver::error::ResolveError,
    ) -> Self {
        Self::TxtLookup {
            name: name.into(),
            source,
        }
    }

    pub(crate) fn txt_data_utf8(name: impl Into<String>, source: std::str::Utf8Error) -> Self {
        Self::TxtDataUtf8 {
            name: name.into(),
            source,
        }
    }
}
