use std::collections::HashMap;

use super::{
    AuthError, AuthLookupOptions, DkimPolicyStatus, DkimSelectorStatus, DmarcStatus,
    check_with_resolver,
    dkim::DkimWeakness,
    resolver::LookupTxt,
    spf::{SpfQualifier, SpfStatus},
};

struct StubResolver {
    records: HashMap<String, Vec<String>>,
}

impl StubResolver {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    fn insert_records<I, S>(&mut self, name: &str, records: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let key = normalize_name(name);
        let values = records.into_iter().map(Into::into).collect();
        self.records.insert(key, values);
    }
}

impl LookupTxt for StubResolver {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError> {
        let key = normalize_name(name);
        Ok(self.records.get(&key).cloned().unwrap_or_default())
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[test]
fn spf_reports_missing_when_no_records() {
    let status = super::spf::evaluate(&[]);
    assert!(matches!(status, SpfStatus::Missing));
}

#[test]
fn spf_softfail_considered_compliant() {
    let input = vec!["v=spf1 include:_spf.example.net ~all".to_string()];
    let status = super::spf::evaluate(&input);
    assert!(matches!(
        status,
        SpfStatus::Compliant {
            qualifier: SpfQualifier::SoftFail,
            ..
        }
    ));
}

#[test]
fn spf_redirect_marked_delegated() {
    let input = vec!["v=spf1 redirect=_spf.example.net".to_string()];
    let status = super::spf::evaluate(&input);
    match status {
        SpfStatus::Delegated { ref target, .. } => assert_eq!(target, "_spf.example.net"),
        other => panic!("expected delegated status, got {:?}", other),
    }
}

#[test]
fn dmarc_none_policy_flagged_weak() {
    let input = vec!["v=DMARC1; p=none; rua=mailto:d@example.com".to_string()];
    let status = super::dmarc::evaluate(&input);
    assert!(matches!(status, DmarcStatus::Weak { .. }));
}

#[test]
fn dkim_testing_selector_reported_weak() {
    let records = vec!["v=DKIM1; p=MIIB...; t=y".to_string()];
    let status = super::dkim::selector_status("default", &records);
    assert!(matches!(
        status,
        DkimSelectorStatus::Weak {
            weakness: DkimWeakness::TestingFlag,
            ..
        }
    ));
}

#[test]
fn check_with_resolver_combines_findings() {
    let mut stub = StubResolver::new();
    stub.insert_records("example.com", vec!["v=spf1 ip4:192.0.2.1 ~all"]);
    stub.insert_records(
        "_dmarc.example.com",
        vec!["v=DMARC1; p=none; rua=mailto:d@example.com"],
    );
    stub.insert_records("_domainkey.example.com", vec!["v=DKIM1; o=-"]);
    stub.insert_records(
        "default._domainkey.example.com",
        vec!["v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A; t=y"],
    );

    let options = AuthLookupOptions::new().with_dkim_selector("default");
    let status = check_with_resolver(&stub, "example.com", &options).expect("resolution succeeds");

    match status.spf {
        SpfStatus::Compliant {
            qualifier: SpfQualifier::SoftFail,
            ..
        } => {}
        ref other => panic!("unexpected SPF status: {:?}", other),
    }

    match status.dmarc {
        DmarcStatus::Weak { .. } => {}
        ref other => panic!("unexpected DMARC status: {:?}", other),
    }

    match status.dkim.policy {
        DkimPolicyStatus::Present { testing: false, .. } => {}
        ref other => panic!("unexpected DKIM policy status: {:?}", other),
    }

    let selector = status
        .dkim
        .selectors
        .iter()
        .find(|entry| matches!(entry, DkimSelectorStatus::Weak { selector, .. } if selector == "default"))
        .unwrap_or_else(|| panic!("expected selector status"));

    if let DkimSelectorStatus::Weak { weakness, .. } = selector {
        assert_eq!(*weakness, DkimWeakness::TestingFlag);
    } else {
        panic!("expected weak selector, got {:?}", selector);
    }
}
