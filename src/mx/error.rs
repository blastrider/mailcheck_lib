use thiserror::Error;

#[derive(Debug, Error)]
pub enum MxError {
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
    #[error("MX lookup failed: {source}")]
    Lookup {
        #[source]
        source: trust_dns_resolver::error::ResolveError,
    },
}

impl MxError {
    pub(crate) fn idna(source: idna::Errors) -> Self {
        Self::IdnaConversion { source }
    }

    pub(crate) fn resolver_init(source: std::io::Error) -> Self {
        Self::ResolverInit { source }
    }

    pub(crate) fn lookup(source: trust_dns_resolver::error::ResolveError) -> Self {
        Self::Lookup { source }
    }
}
