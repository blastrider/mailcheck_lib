use std::net::{SocketAddr, ToSocketAddrs};

use trust_dns_resolver::Resolver;

use crate::smtp_verify::error::SmtpVerifyError;

#[derive(Debug, Clone)]
pub struct HostCandidate {
    pub host: String,
    pub preference: u16,
    pub addresses: Vec<SocketAddr>,
}

pub fn build_resolver() -> Result<Resolver, SmtpVerifyError> {
    Resolver::from_system_conf().map_err(|err| SmtpVerifyError::ResolverInit { source: err })
}

pub fn resolve_hosts(
    resolver: &Resolver,
    domain: &str,
    max_hosts: usize,
    allow_ipv6: bool,
) -> Result<Vec<HostCandidate>, SmtpVerifyError> {
    let mut hosts = lookup_mx(resolver, domain, allow_ipv6)?;
    if hosts.is_empty() {
        // RFC: fall back to implicit MX (A/AAAA records for domain itself)
        let addresses = resolve_addrs(domain, allow_ipv6)?;
        if addresses.is_empty() {
            return Err(SmtpVerifyError::NoSmtpServers);
        }
        hosts.push(HostCandidate {
            host: domain.to_string(),
            preference: 0,
            addresses,
        });
    }

    hosts.sort_by_key(|h| h.preference);
    hosts.truncate(max_hosts.max(1));
    Ok(hosts)
}

fn lookup_mx(
    resolver: &Resolver,
    domain: &str,
    allow_ipv6: bool,
) -> Result<Vec<HostCandidate>, SmtpVerifyError> {
    let mut out = Vec::new();
    match resolver.mx_lookup(domain) {
        Ok(lookup) => {
            for record in lookup.iter() {
                let host = record.exchange().to_utf8();
                let host_trimmed = host.trim_end_matches('.').to_string();
                let addrs = resolve_addrs(&host_trimmed, allow_ipv6)?;
                if addrs.is_empty() {
                    continue;
                }
                out.push(HostCandidate {
                    host: host_trimmed,
                    preference: record.preference(),
                    addresses: addrs,
                });
            }
        }
        Err(err) => match err.kind() {
            trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {}
            _ => return Err(SmtpVerifyError::Lookup { source: err }),
        },
    }
    Ok(out)
}

fn resolve_addrs(domain: &str, allow_ipv6: bool) -> Result<Vec<SocketAddr>, SmtpVerifyError> {
    let mut addrs = Vec::new();
    let query = format!("{domain}:25");
    let iter = query
        .to_socket_addrs()
        .map_err(|err| SmtpVerifyError::Io { source: err })?;
    for addr in iter {
        if !allow_ipv6 && addr.is_ipv6() {
            continue;
        }
        addrs.push(addr);
    }
    Ok(addrs)
}
