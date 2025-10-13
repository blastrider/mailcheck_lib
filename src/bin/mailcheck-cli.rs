use anyhow::{Context, Result};
use clap::CommandFactory;
use clap::{Parser, Subcommand};
use mailcheck_lib::{NormalizedEmail, ValidationMode, normalize_email};

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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut mode = mode_from_str(&cli.mode);
    let mut rows: Vec<NormalizedEmail> = Vec::new();

    if cli.stdin {
        for line in io::stdin().lock().lines() {
            let email = line.context("read stdin")?;
            let r = normalize_email(email.as_str(), mode)?;
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
        let r = normalize_email(&email, mode)?;
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
                        ])?;
                    }
                    let data = wtr.into_inner()?;
                    write_all_atomically(path, &data)?;
                } else {
                    let mut wtr = csv::Writer::from_writer(std::io::stdout());
                    for r in &rows {
                        let reasons = r.reasons.join("|");
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
