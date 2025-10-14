use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use clap::{Parser, Subcommand};
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

#[cfg(feature = "with-mx")]
fn make_row(normalized: NormalizedEmail, cli: &Cli) -> OutputRow {
    let mut row = OutputRow {
        normalized,
        mx: None,
    };
    if cli.mx {
        row.mx = Some(resolve_mx(&row.normalized));
    }
    row
}

#[cfg(not(feature = "with-mx"))]
fn make_row(normalized: NormalizedEmail, _cli: &Cli) -> OutputRow {
    OutputRow { normalized }
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
