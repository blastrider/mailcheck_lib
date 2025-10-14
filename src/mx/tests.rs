use super::{MxRecord, MxStatus, resolver};
use trust_dns_resolver::error::ResolveError;

type LookupResult = Result<Vec<MxRecord>, ResolveError>;
type LookupFn = dyn Fn(&str) -> LookupResult;

pub(crate) struct StubResolver {
    pub on_lookup: Box<LookupFn>,
}

impl StubResolver {
    fn new<F>(f: F) -> Self
    where
        F: Fn(&str) -> LookupResult + 'static,
    {
        Self {
            on_lookup: Box::new(f),
        }
    }
}

#[test]
fn normalize_domain_rejects_empty() {
    let err = resolver::normalize_domain("").expect_err("empty domain should fail");
    assert!(matches!(err, super::Error::EmptyDomain));
}

#[test]
fn resolve_with_sorts_and_dedups_records() {
    let stub = StubResolver::new(|domain| {
        assert_eq!(domain, "example.com");
        Ok(vec![
            MxRecord::new(20, "mx2.example.com"),
            MxRecord::new(10, "mx1.example.com"),
            MxRecord::new(10, "mx1.example.com"),
            MxRecord::new(30, "mx3.example.com"),
        ])
    });

    let status = resolver::resolve_with(&stub, "example.com").expect("lookup succeeds");
    let records = match status {
        MxStatus::Records(records) => records,
        MxStatus::NoRecords => panic!("expected records"),
    };
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].preference, 10);
    assert_eq!(records[0].exchange, "mx1.example.com");
    assert_eq!(records[2].preference, 30);
}

#[test]
fn resolve_with_handles_no_records() {
    let stub = StubResolver::new(|domain| {
        assert_eq!(domain, "example.com");
        Ok(Vec::new())
    });

    let status = resolver::resolve_with(&stub, "example.com").expect("lookup succeeds");
    assert!(matches!(status, MxStatus::NoRecords));
}

#[test]
fn normalize_exchange_trims_dot_and_lowercases() {
    let out = resolver::normalize_exchange("Mail.EXAMPLE.com.".to_string());
    assert_eq!(out, "mail.example.com");
}
