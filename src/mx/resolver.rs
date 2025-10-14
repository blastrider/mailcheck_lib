use trust_dns_resolver::{Resolver, error::ResolveError};

use super::{Error, MxRecord, MxStatus};

/// Lookup MX records for `domain` using the system resolver.
///
/// The domain is normalized via IDNA before querying DNS. The resulting
/// [`MxStatus`] contains the sorted list of records (ascending preference).
pub fn check_mx(domain: &str) -> Result<MxStatus, Error> {
    let ascii = normalize_domain(domain)?;
    let resolver = Resolver::from_system_conf().map_err(Error::resolver_init)?;
    resolve_with(&resolver, &ascii)
}

pub(crate) fn resolve_with<R>(resolver: &R, ascii_domain: &str) -> Result<MxStatus, Error>
where
    R: LookupMx,
{
    let mut records = resolver.lookup_mx(ascii_domain).map_err(Error::lookup)?;

    records.sort();
    records.dedup();

    if records.is_empty() {
        Ok(MxStatus::NoRecords)
    } else {
        Ok(MxStatus::Records(records))
    }
}

pub(crate) fn normalize_domain(domain: &str) -> Result<String, Error> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyDomain);
    }
    idna::domain_to_ascii(trimmed).map_err(Error::idna)
}

pub(crate) fn normalize_exchange(exchange: String) -> String {
    let trimmed = exchange.trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

pub(crate) trait LookupMx {
    fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, ResolveError>;
}

impl LookupMx for Resolver {
    fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, ResolveError> {
        let lookup = Resolver::mx_lookup(self, domain)?;
        let mut records = Vec::new();
        for mx in lookup.iter() {
            let exchange = normalize_exchange(mx.exchange().to_utf8());
            records.push(MxRecord::new(mx.preference(), exchange));
        }
        Ok(records)
    }
}

#[cfg(test)]
impl LookupMx for crate::mx::tests::StubResolver {
    fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, ResolveError> {
        (self.on_lookup)(domain)
    }
}
