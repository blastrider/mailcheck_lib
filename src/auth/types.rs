use super::{dkim::DkimStatus, dmarc::DmarcStatus, spf::SpfStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStatus {
    pub domain: String,
    pub spf: SpfStatus,
    pub dmarc: DmarcStatus,
    pub dkim: DkimStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLookupOptions {
    dkim_selectors: Vec<String>,
    check_dkim_policy: bool,
}

impl AuthLookupOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dkim_selector(mut self, selector: impl Into<String>) -> Self {
        if let Some(normalized) = normalize_selector(selector.into()) {
            if !self.dkim_selectors.contains(&normalized) {
                self.dkim_selectors.push(normalized);
            }
        }
        self
    }

    pub fn with_dkim_selectors<I, S>(mut self, selectors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for selector in selectors {
            self = self.with_dkim_selector(selector);
        }
        self
    }

    pub fn check_policy_record(mut self, value: bool) -> Self {
        self.check_dkim_policy = value;
        self
    }

    pub fn dkim_selectors(&self) -> &[String] {
        &self.dkim_selectors
    }

    pub fn check_dkim_policy(&self) -> bool {
        self.check_dkim_policy
    }
}

impl Default for AuthLookupOptions {
    fn default() -> Self {
        Self {
            dkim_selectors: Vec::new(),
            check_dkim_policy: true,
        }
    }
}

fn normalize_selector(input: String) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

impl AuthStatus {
    pub(crate) fn new(
        domain: String,
        spf: SpfStatus,
        dmarc: DmarcStatus,
        dkim: DkimStatus,
    ) -> Self {
        Self {
            domain,
            spf,
            dmarc,
            dkim,
        }
    }
}
