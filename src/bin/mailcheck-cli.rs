use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use clap::{Parser, Subcommand};
#[cfg(feature = "with-auth-records")]
use mailcheck_lib::{
    AuthError, AuthLookupOptions, AuthStatus, DkimIssue, DkimPolicyStatus, DkimSelectorStatus,
    DkimWeakness, DmarcIssue, DmarcPolicy, DmarcStatus, DmarcWeakness, SpfIssue, SpfQualifier,
    SpfStatus, check_auth_records_with_options,
};
#[cfg(feature = "with-mx")]
use mailcheck_lib::{MxError, MxStatus, check_mx};
use mailcheck_lib::{
    NormalizedEmail, SpecOptions, ValidationMode, normalize_email, normalize_email_with_spec,
};

use std::io::{self, BufRead};

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
struct OutputRow {
    #[cfg_attr(feature = "with-serde", serde(flatten))]
    normalized: NormalizedEmail,
    #[cfg(feature = "with-mx")]
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    mx: Option<MxSummary>,
    #[cfg(feature = "with-auth-records")]
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    auth: Option<AuthSummary>,
}

#[cfg(feature = "with-mx")]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
struct MxSummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    status: Option<MxStatus>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    skipped: Option<String>,
}

#[cfg(feature = "with-mx")]
impl MxSummary {
    fn from_status(status: MxStatus) -> Self {
        Self {
            status: Some(status),
            error: None,
            skipped: None,
        }
    }

    fn from_error(error: &MxError) -> Self {
        Self {
            status: None,
            error: Some(error.to_string()),
            skipped: None,
        }
    }

    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            status: None,
            error: None,
            skipped: Some(reason.into()),
        }
    }

    fn human_summary(&self) -> String {
        if let Some(status) = &self.status {
            match status {
                MxStatus::Records(records) => {
                    if records.is_empty() {
                        "records: <empty>".to_string()
                    } else {
                        let summary = records
                            .iter()
                            .map(|r| format!("{}:{}", r.preference, r.exchange))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("records: {summary}")
                    }
                }
                MxStatus::NoRecords => "no MX records".to_string(),
            }
        } else if let Some(error) = &self.error {
            format!("error: {error}")
        } else if let Some(reason) = &self.skipped {
            format!("skipped: {reason}")
        } else {
            "unknown".to_string()
        }
    }

    #[cfg(feature = "with-csv")]
    fn csv_fields(&self) -> (String, String) {
        if let Some(status) = &self.status {
            match status {
                MxStatus::Records(records) => {
                    let detail = records
                        .iter()
                        .map(|r| format!("{}:{}", r.preference, r.exchange))
                        .collect::<Vec<_>>()
                        .join(";");
                    ("records".to_string(), detail)
                }
                MxStatus::NoRecords => ("no_records".to_string(), String::new()),
            }
        } else if let Some(error) = &self.error {
            ("error".to_string(), error.clone())
        } else if let Some(reason) = &self.skipped {
            ("skipped".to_string(), reason.clone())
        } else {
            ("unknown".to_string(), String::new())
        }
    }
}

#[cfg(feature = "with-auth-records")]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
struct AuthSummary {
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    status: Option<AuthStatusSnapshot>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    error: Option<String>,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    skipped: Option<String>,
}

#[cfg(feature = "with-auth-records")]
impl AuthSummary {
    fn from_status(status: AuthStatus) -> Self {
        Self {
            status: Some(AuthStatusSnapshot::from_status(status)),
            error: None,
            skipped: None,
        }
    }

    fn from_error(error: &AuthError) -> Self {
        Self {
            status: None,
            error: Some(error.to_string()),
            skipped: None,
        }
    }

    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            status: None,
            error: None,
            skipped: Some(reason.into()),
        }
    }

    fn human_lines(&self) -> Vec<String> {
        if let Some(error) = &self.error {
            return vec![format!("error: {error}")];
        }
        if let Some(reason) = &self.skipped {
            return vec![format!("skipped: {reason}")];
        }
        let Some(status) = &self.status else {
            return vec!["unknown".to_string()];
        };

        let mut lines = Vec::new();
        lines.push(format!("domain={}", status.domain));
        lines.push(format!("spf={}", status.spf.summary()));
        lines.push(format!("dmarc={}", status.dmarc.summary()));
        lines.push(format!("dkim_policy={}", status.dkim_policy.summary()));

        if status.selectors.is_empty() {
            lines.push("dkim_selectors=none".to_string());
        } else if status.selectors.len() == 1 {
            let selector = &status.selectors[0];
            lines.push(format!(
                "dkim_selector {} {}",
                selector.selector,
                selector.summary()
            ));
        } else {
            lines.push("dkim_selectors:".to_string());
            for selector in &status.selectors {
                lines.push(format!("  {} {}", selector.selector, selector.summary()));
            }
        }
        lines
    }

    #[cfg(feature = "with-csv")]
    fn csv_fields(&self) -> AuthCsvFields {
        if let Some(status) = &self.status {
            let selectors = if status.selectors.is_empty() {
                String::new()
            } else {
                status
                    .selectors
                    .iter()
                    .map(|selector| format!("{} {}", selector.selector, selector.summary()))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            AuthCsvFields {
                spf: status.spf.summary(),
                dmarc: status.dmarc.summary(),
                dkim_policy: status.dkim_policy.summary(),
                selectors,
                error: String::new(),
                skipped: String::new(),
            }
        } else {
            AuthCsvFields {
                spf: String::new(),
                dmarc: String::new(),
                dkim_policy: String::new(),
                selectors: String::new(),
                error: self.error.clone().unwrap_or_default(),
                skipped: self.skipped.clone().unwrap_or_default(),
            }
        }
    }
}

#[cfg(all(feature = "with-auth-records", feature = "with-csv"))]
struct AuthCsvFields {
    spf: String,
    dmarc: String,
    dkim_policy: String,
    selectors: String,
    error: String,
    skipped: String,
}

#[cfg(all(feature = "with-auth-records", feature = "with-csv"))]
impl AuthCsvFields {
    fn empty() -> Self {
        Self {
            spf: String::new(),
            dmarc: String::new(),
            dkim_policy: String::new(),
            selectors: String::new(),
            error: String::new(),
            skipped: String::new(),
        }
    }
}

#[cfg(feature = "with-auth-records")]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
struct AuthStatusSnapshot {
    domain: String,
    spf: AuthSectionSnapshot,
    dmarc: AuthSectionSnapshot,
    dkim_policy: AuthSectionSnapshot,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Vec::is_empty"))]
    selectors: Vec<AuthSelectorSnapshot>,
}

#[cfg(feature = "with-auth-records")]
impl AuthStatusSnapshot {
    fn from_status(status: AuthStatus) -> Self {
        Self {
            domain: status.domain,
            spf: summarize_spf(&status.spf),
            dmarc: summarize_dmarc(&status.dmarc),
            dkim_policy: summarize_dkim_policy(&status.dkim.policy),
            selectors: status
                .dkim
                .selectors
                .into_iter()
                .map(summarize_selector)
                .collect(),
        }
    }
}

#[cfg(feature = "with-auth-records")]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
struct AuthSectionSnapshot {
    status: String,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    detail: Option<String>,
}

#[cfg(feature = "with-auth-records")]
impl AuthSectionSnapshot {
    fn new(status: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            status: status.into(),
            detail,
        }
    }

    fn summary(&self) -> String {
        if let Some(detail) = &self.detail {
            if detail.is_empty() {
                self.status.clone()
            } else {
                format!("{} ({detail})", self.status)
            }
        } else {
            self.status.clone()
        }
    }
}

#[cfg(feature = "with-auth-records")]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
struct AuthSelectorSnapshot {
    selector: String,
    status: String,
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    detail: Option<String>,
}

#[cfg(feature = "with-auth-records")]
impl AuthSelectorSnapshot {
    fn new(selector: String, status: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            selector,
            status: status.into(),
            detail,
        }
    }

    fn summary(&self) -> String {
        if let Some(detail) = &self.detail {
            if detail.is_empty() {
                self.status.clone()
            } else {
                format!("{} ({detail})", self.status)
            }
        } else {
            self.status.clone()
        }
    }
}

#[cfg(feature = "with-auth-records")]
fn summarize_spf(status: &SpfStatus) -> AuthSectionSnapshot {
    match status {
        SpfStatus::Missing => AuthSectionSnapshot::new("missing", None),
        SpfStatus::MultipleRecords { records } => {
            let detail = if records.is_empty() {
                None
            } else {
                Some(format!("records={}", records.join(" | ")))
            };
            AuthSectionSnapshot::new("multiple_records", detail)
        }
        SpfStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_spf_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
        SpfStatus::Delegated { record, target } => {
            let detail = format!("target={target}; record={record}");
            AuthSectionSnapshot::new("delegated", Some(detail))
        }
        SpfStatus::Weak { record, qualifier } => {
            let detail = format!(
                "qualifier={}; record={record}",
                describe_spf_qualifier(*qualifier)
            );
            AuthSectionSnapshot::new("weak_policy", Some(detail))
        }
        SpfStatus::Compliant { record, qualifier } => {
            let detail = format!(
                "qualifier={}; record={record}",
                describe_spf_qualifier(*qualifier)
            );
            AuthSectionSnapshot::new("compliant", Some(detail))
        }
    }
}

#[cfg(feature = "with-auth-records")]
fn summarize_dmarc(status: &DmarcStatus) -> AuthSectionSnapshot {
    match status {
        DmarcStatus::Missing => AuthSectionSnapshot::new("missing", None),
        DmarcStatus::MultipleRecords { records } => {
            let detail = if records.is_empty() {
                None
            } else {
                Some(format!("records={}", records.join(" | ")))
            };
            AuthSectionSnapshot::new("multiple_records", detail)
        }
        DmarcStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_dmarc_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
        DmarcStatus::Weak {
            record,
            policy,
            weakness,
        } => {
            let detail = format!(
                "policy={}; weakness={}; record={record}",
                describe_dmarc_policy(*policy),
                describe_dmarc_weakness(*weakness)
            );
            AuthSectionSnapshot::new("weak_policy", Some(detail))
        }
        DmarcStatus::Compliant { record, policy } => {
            let detail = format!("policy={}; record={record}", describe_dmarc_policy(*policy));
            AuthSectionSnapshot::new("compliant", Some(detail))
        }
    }
}

#[cfg(feature = "with-auth-records")]
fn summarize_dkim_policy(status: &DkimPolicyStatus) -> AuthSectionSnapshot {
    match status {
        DkimPolicyStatus::NotRequested => AuthSectionSnapshot::new("not_requested", None),
        DkimPolicyStatus::Missing => AuthSectionSnapshot::new("missing", None),
        DkimPolicyStatus::Present { record, testing } => {
            let detail = format!("testing={testing}; record={record}");
            AuthSectionSnapshot::new("present", Some(detail))
        }
        DkimPolicyStatus::Invalid { record, issue } => {
            let detail = format!("issue={}; record={record}", describe_dkim_issue(issue));
            AuthSectionSnapshot::new("invalid", Some(detail))
        }
    }
}

#[cfg(feature = "with-auth-records")]
fn summarize_selector(status: DkimSelectorStatus) -> AuthSelectorSnapshot {
    match status {
        DkimSelectorStatus::Missing { selector } => {
            AuthSelectorSnapshot::new(selector, "missing", None)
        }
        DkimSelectorStatus::Invalid {
            selector,
            records,
            issue,
        } => {
            let detail = if records.is_empty() {
                format!("issue={}", describe_dkim_issue(&issue))
            } else {
                format!(
                    "issue={}; records={}",
                    describe_dkim_issue(&issue),
                    records.join(" | ")
                )
            };
            AuthSelectorSnapshot::new(selector, "invalid", Some(detail))
        }
        DkimSelectorStatus::Weak {
            selector,
            record,
            weakness,
        } => {
            let detail = format!(
                "weakness={}; record={record}",
                describe_dkim_weakness(weakness)
            );
            AuthSelectorSnapshot::new(selector, "weak", Some(detail))
        }
        DkimSelectorStatus::Compliant { selector, record } => {
            let detail = format!("record={record}");
            AuthSelectorSnapshot::new(selector, "compliant", Some(detail))
        }
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_spf_issue(issue: &SpfIssue) -> &'static str {
    match issue {
        SpfIssue::InvalidVersion => "invalid_version",
        SpfIssue::MissingAllMechanism => "missing_all_mechanism",
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_spf_qualifier(qualifier: SpfQualifier) -> &'static str {
    match qualifier {
        SpfQualifier::Fail => "-all",
        SpfQualifier::SoftFail => "~all",
        SpfQualifier::Neutral => "?all",
        SpfQualifier::Pass => "+all",
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_dmarc_issue(issue: &DmarcIssue) -> String {
    match issue {
        DmarcIssue::InvalidVersion => "invalid_version".to_string(),
        DmarcIssue::MissingPolicy => "missing_policy".to_string(),
        DmarcIssue::UnknownPolicy { policy } => format!("unknown_policy({policy})"),
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_dmarc_policy(policy: DmarcPolicy) -> &'static str {
    match policy {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_dmarc_weakness(weakness: DmarcWeakness) -> &'static str {
    match weakness {
        DmarcWeakness::MonitoringPolicy => "monitoring_policy",
        DmarcWeakness::QuarantinePolicy => "quarantine_policy",
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_dkim_issue(issue: &DkimIssue) -> String {
    match issue {
        DkimIssue::InvalidVersion => "invalid_version".to_string(),
        DkimIssue::MissingPublicKey => "missing_public_key".to_string(),
        DkimIssue::MultipleRecords { count } => format!("multiple_records({count})"),
    }
}

#[cfg(feature = "with-auth-records")]
fn describe_dkim_weakness(weakness: DkimWeakness) -> &'static str {
    match weakness {
        DkimWeakness::TestingFlag => "testing_flag",
    }
}

#[derive(Parser)]
#[command(name = "mailcheck-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,

    /// lit des adresses depuis stdin (une par ligne)
    #[arg(long)]
    stdin: bool,

    /// write report to file (JSON/NDJSON/CSV selon --format)
    #[arg(long)]
    out: Option<String>,

    /// mode: strict|relaxed
    #[arg(long, default_value = "strict")]
    mode: String,

    /// format: human|json|ndjson|csv
    #[arg(long, default_value = "human")]
    format: String,

    /// active la détection de caractères spéciaux/typosquatting
    #[arg(long)]
    spec_chars: bool,

    /// profil: standard|strict|fr-fraud
    #[arg(long, default_value = "standard")]
    spec_profile: String,

    /// dump SpecCharacters (JSON par ligne)
    #[arg(long)]
    spec_json: bool,

    /// force la génération du hint ASCII
    #[arg(long)]
    ascii_hint: bool,

    /// résout les enregistrements MX du domaine (feature `with-mx`)
    #[cfg(feature = "with-mx")]
    #[arg(long)]
    mx: bool,

    /// vérifie les enregistrements SPF/DKIM/DMARC (feature `with-auth-records`)
    #[cfg(feature = "with-auth-records")]
    #[arg(long)]
    auth: bool,

    /// ajoute un sélecteur DKIM à interroger (répétable)
    #[cfg(feature = "with-auth-records")]
    #[arg(long = "dkim-selector")]
    dkim_selectors: Vec<String>,

    /// ignore l'enregistrement de politique DKIM (_domainkey)
    #[cfg(feature = "with-auth-records")]
    #[arg(long)]
    skip_dkim_policy: bool,
}

#[derive(Subcommand)]
enum Commands {
    Validate {
        /// mode: strict|relaxed (prend le pas sur l'option globale)
        #[arg(long)]
        mode: Option<String>,
        email: String,
    },
}

fn mode_from_str(s: &str) -> ValidationMode {
    match s {
        "relaxed" => ValidationMode::Relaxed,
        _ => ValidationMode::Strict,
    }
}

fn spec_options_from_profile(profile: &str) -> Result<SpecOptions> {
    match profile {
        "standard" => Ok(SpecOptions::standard()),
        "strict" => Ok(SpecOptions::strict()),
        "fr-fraud" => Ok(SpecOptions::fr_fraud()),
        other => bail!("unknown --spec-profile '{other}'"),
    }
}

#[cfg(feature = "with-csv")]
fn bool_opt_str(opt: Option<bool>) -> &'static str {
    match opt {
        Some(true) => "true",
        Some(false) => "false",
        None => "",
    }
}

fn format_spec_summary(row: &NormalizedEmail) -> Option<String> {
    let spec = row.spec_chars.as_ref()?;
    let mut parts = vec![
        format!("confusables={}", spec.has_confusables),
        format!("diacritics={}", spec.has_diacritics),
        format!("mixed_scripts={}", spec.has_mixed_scripts),
    ];
    if let Some(notes) = row.spec_notes.as_ref() {
        if !notes.is_empty() {
            parts.push(format!("notes={notes}"));
        }
    }
    if let Some(hint) = row.ascii_hint.as_ref() {
        if !hint.is_empty() {
            parts.push(format!("ascii_hint={hint}"));
        }
    }
    Some(parts.join(", "))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut mode = mode_from_str(&cli.mode);
    let mut rows: Vec<OutputRow> = Vec::new();

    let spec_requested = cli.spec_chars || cli.spec_json || cli.ascii_hint;
    let mut spec_options = if spec_requested {
        Some(spec_options_from_profile(&cli.spec_profile)?)
    } else {
        None
    };

    if let Some(ref mut opts) = spec_options {
        if cli.ascii_hint {
            opts.ascii_hint = true;
        }
    }

    if cli.stdin {
        for line in io::stdin().lock().lines() {
            let email = line.context("read stdin")?;
            let r = if let Some(ref opts) = spec_options {
                normalize_email_with_spec(email.as_str(), mode, Some(opts.clone()))?
            } else {
                normalize_email(email.as_str(), mode)?
            };
            rows.push(make_row(r, &cli));
        }
    } else if let Some(Commands::Validate {
        mode: sub_mode,
        email,
    }) = &cli.cmd
    {
        if let Some(m) = sub_mode.as_deref() {
            mode = mode_from_str(m); // la sous-commande a priorité
        }
        let r = if let Some(ref opts) = spec_options {
            normalize_email_with_spec(email.as_str(), mode, Some(opts.clone()))?
        } else {
            normalize_email(email.as_str(), mode)?
        };
        rows.push(make_row(r, &cli));
    } else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // sortie
    match cli.format.as_str() {
        "human" => {
            for row in &rows {
                let normalized = &row.normalized;
                if normalized.valid {
                    println!("[OK]    {}", normalized.original);
                } else {
                    println!(
                        "[INVALID] {} :: {}",
                        normalized.original,
                        normalized.reasons.join("; ")
                    );
                }
                if spec_requested {
                    if let Some(summary) = format_spec_summary(normalized) {
                        println!("        spec: {summary}");
                    }
                }
                #[cfg(feature = "with-mx")]
                if let Some(mx) = &row.mx {
                    println!("        mx: {}", mx.human_summary());
                }
                #[cfg(feature = "with-auth-records")]
                if let Some(auth) = &row.auth {
                    let lines = auth.human_lines();
                    for (idx, line) in lines.iter().enumerate() {
                        if idx == 0 {
                            println!("        auth: {line}");
                        } else {
                            println!("              {line}");
                        }
                    }
                }
            }
        }
        "json" => {
            #[cfg(feature = "with-serde")]
            {
                let s = serde_json::to_string_pretty(&rows)?;
                if let Some(path) = cli.out {
                    write_all_atomically(&path, s.as_bytes())?;
                } else {
                    println!("{s}");
                }
            }
            #[cfg(not(feature = "with-serde"))]
            {
                eprintln!("format=json nécessite la feature 'with-serde'");
                std::process::exit(1);
            }
        }
        "ndjson" => {
            #[cfg(feature = "with-serde")]
            {
                if let Some(path) = &cli.out {
                    let mut buf = Vec::new();
                    for r in &rows {
                        let line = serde_json::to_string(r)?;
                        buf.extend_from_slice(line.as_bytes());
                        buf.push(b'\n');
                    }
                    write_all_atomically(path, &buf)?;
                } else {
                    for r in &rows {
                        println!("{}", serde_json::to_string(r)?);
                    }
                }
            }
            #[cfg(not(feature = "with-serde"))]
            {
                eprintln!("format=ndjson nécessite la feature 'with-serde'");
                std::process::exit(1);
            }
        }
        "csv" => {
            #[cfg(feature = "with-csv")]
            {
                if let Some(path) = &cli.out {
                    let mut wtr = csv::Writer::from_writer(Vec::new());
                    for row in &rows {
                        let normalized = &row.normalized;
                        let reasons = normalized.reasons.join("|");
                        let spec_notes = normalized.spec_notes.as_deref().unwrap_or("");
                        let ascii_hint = normalized.ascii_hint.as_deref().unwrap_or("");
                        let mut record = vec![
                            normalized.original.clone(),
                            normalized.local.clone(),
                            normalized.domain.clone(),
                            normalized.ascii_domain.clone(),
                            match normalized.mode {
                                ValidationMode::Strict => "strict",
                                ValidationMode::Relaxed => "relaxed",
                            }
                            .to_string(),
                            if normalized.valid {
                                "true".to_string()
                            } else {
                                "false".to_string()
                            },
                            reasons,
                            bool_opt_str(normalized.has_confusables).to_string(),
                            bool_opt_str(normalized.has_diacritics).to_string(),
                            bool_opt_str(normalized.has_mixed_scripts).to_string(),
                            spec_notes.to_string(),
                            ascii_hint.to_string(),
                        ];
                        #[cfg(feature = "with-mx")]
                        if cli.mx {
                            let (status, detail) = row
                                .mx
                                .as_ref()
                                .map(|mx| mx.csv_fields())
                                .unwrap_or_else(|| (String::new(), String::new()));
                            record.push(status);
                            record.push(detail);
                        }
                        #[cfg(feature = "with-auth-records")]
                        if cli.auth {
                            let fields = row
                                .auth
                                .as_ref()
                                .map(|auth| auth.csv_fields())
                                .unwrap_or_else(AuthCsvFields::empty);
                            record.push(fields.spf);
                            record.push(fields.dmarc);
                            record.push(fields.dkim_policy);
                            record.push(fields.selectors);
                            record.push(fields.error);
                            record.push(fields.skipped);
                        }
                        wtr.write_record(&record)?;
                    }
                    let data = wtr.into_inner()?;
                    write_all_atomically(path, &data)?;
                } else {
                    let mut wtr = csv::Writer::from_writer(std::io::stdout());
                    for row in &rows {
                        let normalized = &row.normalized;
                        let reasons = normalized.reasons.join("|");
                        let spec_notes = normalized.spec_notes.as_deref().unwrap_or("");
                        let ascii_hint = normalized.ascii_hint.as_deref().unwrap_or("");
                        let mut record = vec![
                            normalized.original.clone(),
                            normalized.local.clone(),
                            normalized.domain.clone(),
                            normalized.ascii_domain.clone(),
                            match normalized.mode {
                                ValidationMode::Strict => "strict",
                                ValidationMode::Relaxed => "relaxed",
                            }
                            .to_string(),
                            if normalized.valid {
                                "true".to_string()
                            } else {
                                "false".to_string()
                            },
                            reasons,
                            bool_opt_str(normalized.has_confusables).to_string(),
                            bool_opt_str(normalized.has_diacritics).to_string(),
                            bool_opt_str(normalized.has_mixed_scripts).to_string(),
                            spec_notes.to_string(),
                            ascii_hint.to_string(),
                        ];
                        #[cfg(feature = "with-mx")]
                        if cli.mx {
                            let (status, detail) = row
                                .mx
                                .as_ref()
                                .map(|mx| mx.csv_fields())
                                .unwrap_or_else(|| (String::new(), String::new()));
                            record.push(status);
                            record.push(detail);
                        }
                        #[cfg(feature = "with-auth-records")]
                        if cli.auth {
                            let fields = row
                                .auth
                                .as_ref()
                                .map(|auth| auth.csv_fields())
                                .unwrap_or_else(AuthCsvFields::empty);
                            record.push(fields.spf);
                            record.push(fields.dmarc);
                            record.push(fields.dkim_policy);
                            record.push(fields.selectors);
                            record.push(fields.error);
                            record.push(fields.skipped);
                        }
                        wtr.write_record(&record)?;
                    }
                    wtr.flush()?;
                }
            }
            #[cfg(not(feature = "with-csv"))]
            {
                eprintln!("format=csv nécessite la feature 'with-csv'");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("unknown --format '{}', use: human|json|ndjson|csv", other);
            std::process::exit(1);
        }
    }

    if cli.spec_json {
        #[cfg(feature = "with-serde")]
        {
            for row in &rows {
                if let Some(spec) = &row.normalized.spec_chars {
                    println!("{}", serde_json::to_string(spec)?);
                } else {
                    println!("null");
                }
            }
        }
        #[cfg(not(feature = "with-serde"))]
        {
            eprintln!("--spec-json nécessite la feature 'with-serde'");
            std::process::exit(1);
        }
    }

    // codes de sortie : 0 OK, 2 invalids, 1 fatal
    let any_invalid = rows.iter().any(|row| !row.normalized.valid);
    if any_invalid {
        std::process::exit(2);
    }
    Ok(())
}

fn make_row(normalized: NormalizedEmail, cli: &Cli) -> OutputRow {
    let mut row = OutputRow {
        normalized,
        #[cfg(feature = "with-mx")]
        mx: None,
        #[cfg(feature = "with-auth-records")]
        auth: None,
    };

    #[cfg(feature = "with-mx")]
    if cli.mx {
        row.mx = Some(resolve_mx(&row.normalized));
    }

    #[cfg(feature = "with-auth-records")]
    if cli.auth {
        row.auth = Some(resolve_auth(&row.normalized, cli));
    }

    row
}

#[cfg(feature = "with-mx")]
fn resolve_mx(row: &NormalizedEmail) -> MxSummary {
    let target = if !row.ascii_domain.is_empty() {
        row.ascii_domain.as_str()
    } else {
        row.domain.as_str()
    };
    if target.trim().is_empty() {
        return MxSummary::skipped("domain missing");
    }

    match check_mx(target) {
        Ok(status) => MxSummary::from_status(status),
        Err(MxError::EmptyDomain) => MxSummary::skipped("domain missing"),
        Err(err) => MxSummary::from_error(&err),
    }
}

#[cfg(feature = "with-auth-records")]
fn resolve_auth(row: &NormalizedEmail, cli: &Cli) -> AuthSummary {
    let target = if !row.ascii_domain.is_empty() {
        row.ascii_domain.as_str()
    } else {
        row.domain.as_str()
    };
    if target.trim().is_empty() {
        return AuthSummary::skipped("domain missing");
    }

    let mut options = AuthLookupOptions::new();
    if cli.skip_dkim_policy {
        options = options.check_policy_record(false);
    }
    if !cli.dkim_selectors.is_empty() {
        options = options.with_dkim_selectors(cli.dkim_selectors.iter().cloned());
    }

    match check_auth_records_with_options(target, &options) {
        Ok(status) => AuthSummary::from_status(status),
        Err(AuthError::EmptyDomain) => AuthSummary::skipped("domain missing"),
        Err(err) => AuthSummary::from_error(&err),
    }
}

#[cfg(any(feature = "with-serde", feature = "with-csv"))]
fn write_all_atomically(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = format!("{}.tmp", path);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
