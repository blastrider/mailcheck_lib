#[cfg(any(feature = "with-serde", feature = "with-csv"))]
use anyhow::Context;
use anyhow::{Result, bail};

use crate::args::Cli;
use mailcheck_lib::NormalizedEmail;
#[cfg(feature = "with-csv")]
use mailcheck_lib::ValidationMode;

#[cfg(all(feature = "with-auth-records", feature = "with-csv"))]
use crate::auth::AuthCsvFields;
#[cfg(feature = "with-auth-records")]
use crate::auth::AuthSummary;
#[cfg(feature = "with-smtp-verify")]
use crate::deliverability::DeliverabilitySummary;
#[cfg(feature = "with-mx")]
use crate::mx::MxSummary;

#[cfg(feature = "with-auth-records")]
use crate::auth;
#[cfg(feature = "with-smtp-verify")]
use crate::deliverability;
#[cfg(feature = "with-mx")]
use crate::mx;

#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
pub struct OutputRow {
    #[cfg_attr(feature = "with-serde", serde(flatten))]
    pub normalized: NormalizedEmail,
    #[cfg(feature = "with-mx")]
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mx: Option<MxSummary>,
    #[cfg(feature = "with-smtp-verify")]
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub deliverability: Option<DeliverabilitySummary>,
    #[cfg(feature = "with-auth-records")]
    #[cfg_attr(feature = "with-serde", serde(skip_serializing_if = "Option::is_none"))]
    pub auth: Option<AuthSummary>,
}

impl OutputRow {
    pub fn new(normalized: NormalizedEmail) -> Self {
        Self {
            normalized,
            #[cfg(feature = "with-mx")]
            mx: None,
            #[cfg(feature = "with-smtp-verify")]
            deliverability: None,
            #[cfg(feature = "with-auth-records")]
            auth: None,
        }
    }
}

#[cfg_attr(
    not(any(feature = "with-mx", feature = "with-auth-records")),
    allow(unused_variables, unused_mut)
)]
pub fn make_row(normalized: NormalizedEmail, cli: &Cli) -> OutputRow {
    let mut row = OutputRow::new(normalized);

    #[cfg(feature = "with-mx")]
    if cli.mx {
        row.mx = Some(mx::resolve(&row.normalized));
    }

    #[cfg(feature = "with-smtp-verify")]
    if cli.deliverability {
        row.deliverability = Some(deliverability::probe(&row.normalized));
    }

    #[cfg(feature = "with-auth-records")]
    if cli.auth {
        row.auth = Some(auth::resolve(
            &row.normalized,
            cli.skip_dkim_policy,
            &cli.dkim_selectors,
        ));
    }

    row
}

pub fn write_reports(rows: &[OutputRow], cli: &Cli) -> Result<()> {
    match cli.format.as_str() {
        "human" => write_human(rows, cli),
        "json" => write_json(rows, cli),
        "ndjson" => write_ndjson(rows, cli),
        "csv" => write_csv(rows, cli),
        other => bail!("unknown --format '{other}', use: human|json|ndjson|csv"),
    }
}

#[cfg(feature = "with-serde")]
pub fn write_spec_json(rows: &[OutputRow]) -> Result<()> {
    for row in rows {
        if let Some(spec) = &row.normalized.spec_chars {
            println!("{}", serde_json::to_string(spec)?);
        } else {
            println!("null");
        }
    }
    Ok(())
}

#[cfg(not(feature = "with-serde"))]
pub fn write_spec_json(_rows: &[OutputRow]) -> Result<()> {
    bail!("--spec-json nécessite la feature 'with-serde'")
}

pub fn any_invalid(rows: &[OutputRow]) -> bool {
    rows.iter().any(|row| !row.normalized.valid)
}

fn write_human(rows: &[OutputRow], cli: &Cli) -> Result<()> {
    let spec_requested = cli.spec_requested();
    for row in rows {
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

        #[cfg(feature = "with-smtp-verify")]
        if let Some(deliv) = &row.deliverability {
            println!("        smtp: {}", deliv.human_summary());
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
    Ok(())
}

#[cfg(feature = "with-serde")]
fn write_json(rows: &[OutputRow], cli: &Cli) -> Result<()> {
    let s = serde_json::to_string_pretty(rows)?;
    if let Some(path) = &cli.out {
        write_all_atomically(path, s.as_bytes())?;
    } else {
        println!("{s}");
    }
    Ok(())
}

#[cfg(not(feature = "with-serde"))]
fn write_json(_: &[OutputRow], _: &Cli) -> Result<()> {
    bail!("format=json nécessite la feature 'with-serde'")
}

#[cfg(feature = "with-serde")]
fn write_ndjson(rows: &[OutputRow], cli: &Cli) -> Result<()> {
    if let Some(path) = &cli.out {
        let mut buf = Vec::new();
        for row in rows {
            let line = serde_json::to_string(row)?;
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        write_all_atomically(path, &buf)?;
    } else {
        for row in rows {
            println!("{}", serde_json::to_string(row)?);
        }
    }
    Ok(())
}

#[cfg(not(feature = "with-serde"))]
fn write_ndjson(_: &[OutputRow], _: &Cli) -> Result<()> {
    bail!("format=ndjson nécessite la feature 'with-serde'")
}

#[cfg(feature = "with-csv")]
fn write_csv(rows: &[OutputRow], cli: &Cli) -> Result<()> {
    if let Some(path) = &cli.out {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        for row in rows {
            let record = csv_record(row, cli);
            wtr.write_record(&record)?;
        }
        let data = wtr.into_inner()?;
        write_all_atomically(path, &data)?;
    } else {
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        for row in rows {
            let record = csv_record(row, cli);
            wtr.write_record(&record)?;
        }
        wtr.flush()?;
    }
    Ok(())
}

#[cfg(not(feature = "with-csv"))]
fn write_csv(_: &[OutputRow], _: &Cli) -> Result<()> {
    bail!("format=csv nécessite la feature 'with-csv'")
}

#[cfg(feature = "with-csv")]
fn csv_record(row: &OutputRow, cli: &Cli) -> Vec<String> {
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

    #[cfg(feature = "with-smtp-verify")]
    if cli.deliverability {
        let (status, detail) = row
            .deliverability
            .as_ref()
            .map(|summary| summary.csv_fields())
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

    record
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

#[cfg(any(feature = "with-serde", feature = "with-csv"))]
fn write_all_atomically(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp} -> {path}"))?;
    Ok(())
}
