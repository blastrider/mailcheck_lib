mod dkim;
mod dmarc;
mod error;
mod resolver;
mod spf;
mod types;

pub use dkim::{DkimIssue, DkimPolicyStatus, DkimSelectorStatus, DkimStatus, DkimWeakness};
pub use dmarc::{DmarcIssue, DmarcPolicy, DmarcStatus, DmarcWeakness};
pub use error::AuthError;
pub use spf::{SpfIssue, SpfQualifier, SpfStatus};
pub use types::{AuthLookupOptions, AuthStatus};

use resolver::{LookupTxt, fqdn, normalize_domain};
use trust_dns_resolver::Resolver;

pub fn check_auth_records(domain: &str) -> Result<AuthStatus, AuthError> {
    check_auth_records_with_options(domain, &AuthLookupOptions::default())
}

pub fn check_auth_records_with_options(
    domain: &str,
    options: &AuthLookupOptions,
) -> Result<AuthStatus, AuthError> {
    let ascii = normalize_domain(domain)?;
    let resolver = Resolver::from_system_conf().map_err(AuthError::resolver_init)?;
    check_with_resolver(&resolver, &ascii, options)
}

pub(crate) fn check_with_resolver<R>(
    resolver: &R,
    ascii_domain: &str,
    options: &AuthLookupOptions,
) -> Result<AuthStatus, AuthError>
where
    R: LookupTxt,
{
    let spf_records = resolver.lookup_txt(ascii_domain)?;
    let spf_status = spf::evaluate(&spf_records);

    let dmarc_name = fqdn("_dmarc", ascii_domain);
    let dmarc_records = resolver.lookup_txt(&dmarc_name)?;
    let dmarc_status = dmarc::evaluate(&dmarc_records);

    let policy_status = if options.check_dkim_policy() {
        let policy_name = fqdn("_domainkey", ascii_domain);
        let policy_records = resolver.lookup_txt(&policy_name)?;
        dkim::policy_status(&policy_records)
    } else {
        dkim::policy_not_requested()
    };

    let mut selector_statuses = Vec::new();
    for selector in options.dkim_selectors() {
        let selector_name = fqdn(&format!("{}._domainkey", selector), ascii_domain);
        let selector_records = resolver.lookup_txt(&selector_name)?;
        selector_statuses.push(dkim::selector_status(selector, &selector_records));
    }

    let dkim_status = dkim::assemble_status(policy_status, selector_statuses);

    Ok(AuthStatus::new(
        ascii_domain.to_string(),
        spf_status,
        dmarc_status,
        dkim_status,
    ))
}

#[cfg(test)]
mod tests;
