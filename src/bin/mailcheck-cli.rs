use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use clap::{Parser, Subcommand};
use mailcheck_lib::{
    NormalizedEmail, SpecOptions, ValidationMode, normalize_email, normalize_email_with_spec,
};

use std::io::{self, BufRead};

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
    let mut rows: Vec<NormalizedEmail> = Vec::new();

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
            rows.push(r);
        }
    } else if let Some(Commands::Validate {
        mode: sub_mode,
        email,
    }) = cli.cmd
    {
        if let Some(m) = sub_mode.as_deref() {
            mode = mode_from_str(m); // la sous-commande a priorité
        }
        let r = if let Some(ref opts) = spec_options {
            normalize_email_with_spec(&email, mode, Some(opts.clone()))?
        } else {
            normalize_email(&email, mode)?
        };
        rows.push(r);
    } else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // sortie
    match cli.format.as_str() {
        "human" => {
            for r in &rows {
                if r.valid {
                    println!("[OK]    {}", r.original);
                } else {
                    println!("[INVALID] {} :: {}", r.original, r.reasons.join("; "));
                }
                if spec_requested {
                    if let Some(summary) = format_spec_summary(r) {
                        println!("        spec: {summary}");
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
                    for r in &rows {
                        // On écrit des colonnes stables et lisibles
                        let reasons = r.reasons.join("|");
                        let spec_notes = r.spec_notes.as_deref().unwrap_or("");
                        let ascii_hint = r.ascii_hint.as_deref().unwrap_or("");
                        wtr.write_record([
                            r.original.as_str(),
                            r.local.as_str(),
                            r.domain.as_str(),
                            r.ascii_domain.as_str(),
                            match r.mode {
                                ValidationMode::Strict => "strict",
                                ValidationMode::Relaxed => "relaxed",
                            },
                            if r.valid { "true" } else { "false" },
                            reasons.as_str(),
                            bool_opt_str(r.has_confusables),
                            bool_opt_str(r.has_diacritics),
                            bool_opt_str(r.has_mixed_scripts),
                            spec_notes,
                            ascii_hint,
                        ])?;
                    }
                    let data = wtr.into_inner()?;
                    write_all_atomically(path, &data)?;
                } else {
                    let mut wtr = csv::Writer::from_writer(std::io::stdout());
                    for r in &rows {
                        let reasons = r.reasons.join("|");
                        let spec_notes = r.spec_notes.as_deref().unwrap_or("");
                        let ascii_hint = r.ascii_hint.as_deref().unwrap_or("");
                        wtr.write_record([
                            r.original.as_str(),
                            r.local.as_str(),
                            r.domain.as_str(),
                            r.ascii_domain.as_str(),
                            match r.mode {
                                ValidationMode::Strict => "strict",
                                ValidationMode::Relaxed => "relaxed",
                            },
                            if r.valid { "true" } else { "false" },
                            reasons.as_str(),
                            bool_opt_str(r.has_confusables),
                            bool_opt_str(r.has_diacritics),
                            bool_opt_str(r.has_mixed_scripts),
                            spec_notes,
                            ascii_hint,
                        ])?;
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
            for r in &rows {
                if let Some(spec) = &r.spec_chars {
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
    let any_invalid = rows.iter().any(|r| !r.valid);
    if any_invalid {
        std::process::exit(2);
    }
    Ok(())
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
