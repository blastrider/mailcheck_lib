use anyhow::{Context, Result};
use clap::CommandFactory; // << nécessaire pour Cli::command()
use clap::{Parser, Subcommand};
use mailcheck_lib::{ValidationMode, ValidationReport, validate_email};

#[cfg(feature = "with-serde")]
use std::fs::File;
use std::io::{self, BufRead};

#[derive(Parser)]
#[command(name = "mailcheck-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,

    /// lit des adresses depuis stdin (une par ligne)
    #[arg(long)]
    stdin: bool,

    /// write JSON report to file (atomic) — nécessite feature `with-serde`
    #[arg(long)]
    out: Option<String>,

    /// mode: strict|relaxed
    #[arg(long, default_value = "strict")]
    mode: String,
}

#[derive(Subcommand)]
enum Commands {
    Validate { email: String },
}

fn mode_from_str(s: &str) -> ValidationMode {
    match s {
        "relaxed" => ValidationMode::Relaxed,
        _ => ValidationMode::Strict,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mode = mode_from_str(&cli.mode);
    let mut reports: Vec<ValidationReport> = Vec::new();

    if cli.stdin {
        for line in io::stdin().lock().lines() {
            let email = line.context("read stdin")?;
            let r = validate_email(email.as_str(), mode)?;
            reports.push(r);
        }
    } else if let Some(Commands::Validate { email }) = cli.cmd {
        let report = validate_email(&email, mode)?;
        reports.push(report);
    } else {
        // afficher l'aide si aucune commande fournie
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    if let Some(path) = cli.out {
        // écriture atomique: tempfile + rename
        #[cfg(feature = "with-serde")]
        {
            let tmp = format!("{}.tmp", path);
            let f = File::create(&tmp).context("create temp report file")?;
            serde_json::to_writer_pretty(f, &reports).context("write json report")?;
            std::fs::rename(&tmp, &path).context("rename temp report file")?;
        }
        #[cfg(not(feature = "with-serde"))]
        {
            // <- on UTILISE 'path' ici: message explicite + validation du dossier
            use std::path::Path;
            let parent = Path::new(&path).parent().and_then(|p| {
                if p.as_os_str().is_empty() {
                    None
                } else {
                    Some(p)
                }
            });
            if let Some(dir) = parent {
                if !dir.exists() {
                    eprintln!(
                        "--out: dossier inexistant pour le chemin fourni: '{}'",
                        dir.display()
                    );
                }
            }
            eprintln!(
                "--out demandé pour '{}' mais nécessite la feature 'with-serde'. \
             Recompile : cargo run --features with-serde -- ...",
                path
            );
            std::process::exit(1);
        }
    }

    // 0 = tout OK, 2 = invalids, 1 = fatal (on n'utilise 1 que si erreurs I/O/CLI)
    let any_invalid = reports.iter().any(|r| !r.ok);
    if any_invalid {
        std::process::exit(2);
    }
    Ok(())
}
