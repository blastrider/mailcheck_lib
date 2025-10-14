use trust_dns_resolver::{
    Resolver,
    error::{ResolveError, ResolveErrorKind},
    lookup::TxtLookup,
};

use super::AuthError;

pub(crate) fn normalize_domain(domain: &str) -> Result<String, AuthError> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(AuthError::EmptyDomain);
    }
    idna::domain_to_ascii(trimmed).map_err(AuthError::idna)
}

pub(crate) fn fqdn(label: &str, domain: &str) -> String {
    let trimmed = label.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        domain.to_string()
    } else {
        format!("{}.{}", trimmed.to_ascii_lowercase(), domain)
    }
}

pub(crate) trait LookupTxt {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError>;
}

impl LookupTxt for Resolver {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError> {
        let lookup = match Resolver::txt_lookup(self, name) {
            Ok(lookup) => lookup,
            Err(err) => {
                if should_treat_as_empty(&err) {
                    return Ok(Vec::new());
                }
                return Err(AuthError::txt_lookup(name, err));
            }
        };
        collect_txt_records(name, &lookup)
    }
}

fn collect_txt_records(name: &str, lookup: &TxtLookup) -> Result<Vec<String>, AuthError> {
    let mut records = Vec::new();
    for txt in lookup.iter() {
        let mut record = String::new();
        for piece in txt.txt_data().iter() {
            let segment = std::str::from_utf8(piece.as_ref())
                .map_err(|err| AuthError::txt_data_utf8(name, err))?;
            record.push_str(segment);
        }
        records.push(record);
    }
    Ok(records)
}

fn should_treat_as_empty(err: &ResolveError) -> bool {
    matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. })
}
