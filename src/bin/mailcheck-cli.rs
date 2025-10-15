#[path = "mailcheck-cli/args.rs"]
mod args;
#[cfg(feature = "with-auth-records")]
#[path = "mailcheck-cli/auth.rs"]
mod auth;
#[cfg(feature = "with-mx")]
#[path = "mailcheck-cli/deliverability.rs"]
mod deliverability;
#[cfg(feature = "with-mx")]
#[path = "mailcheck-cli/mx.rs"]
mod mx;
#[path = "mailcheck-cli/output.rs"]
mod output;

use anyhow::{Context, Result};
use args::{Cli, Commands, mode_from_str, spec_options_from_profile};
use mailcheck_lib::{SpecOptions, ValidationMode, normalize_email, normalize_email_with_spec};
use output::{OutputRow, any_invalid, make_row, write_reports, write_spec_json};

use std::io::{self, BufRead};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut mode = cli.parsed_mode();
    let mut rows = Vec::new();

    let spec_requested = cli.spec_requested();
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
        collect_from_stdin(&cli, mode, &mut rows, spec_options.as_ref())?;
    } else if let Some(Commands::Validate {
        mode: sub_mode,
        email,
    }) = &cli.cmd
    {
        if let Some(selected) = sub_mode.as_deref() {
            mode = mode_from_str(selected);
        }
        let normalized = normalize_entry(email.as_str(), mode, spec_options.as_ref())?;
        rows.push(make_row(normalized, &cli));
    } else {
        args::Cli::clap_command().print_help()?;
        println!();
        return Ok(());
    }

    write_reports(&rows, &cli)?;

    if cli.spec_json {
        write_spec_json(&rows)?;
    }

    if any_invalid(&rows) {
        std::process::exit(2);
    }

    Ok(())
}

fn collect_from_stdin(
    cli: &Cli,
    mode: ValidationMode,
    rows: &mut Vec<OutputRow>,
    spec_options: Option<&SpecOptions>,
) -> Result<()> {
    for line in io::stdin().lock().lines() {
        let email = line.context("read stdin")?;
        let normalized = normalize_entry(email.as_str(), mode, spec_options)?;
        rows.push(make_row(normalized, cli));
    }
    Ok(())
}

fn normalize_entry(
    email: &str,
    mode: ValidationMode,
    spec_options: Option<&SpecOptions>,
) -> Result<mailcheck_lib::NormalizedEmail> {
    match spec_options {
        Some(opts) => Ok(normalize_email_with_spec(email, mode, Some(opts.clone()))?),
        None => Ok(normalize_email(email, mode)?),
    }
}
