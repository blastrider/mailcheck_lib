use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use mailcheck_lib::{SpecOptions, ValidationMode};

#[derive(Parser)]
#[command(name = "mailcheck-cli")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Commands>,

    /// lit des adresses depuis stdin (une par ligne)
    #[arg(long)]
    pub stdin: bool,

    /// write report to file (JSON/NDJSON/CSV selon --format)
    #[arg(long)]
    pub out: Option<String>,

    /// mode: strict|relaxed
    #[arg(long, default_value = "strict")]
    pub mode: String,

    /// format: human|json|ndjson|csv
    #[arg(long, default_value = "human")]
    pub format: String,

    /// active la détection de caractères spéciaux/typosquatting
    #[arg(long)]
    pub spec_chars: bool,

    /// profil: standard|strict|fr-fraud
    #[arg(long, default_value = "standard")]
    pub spec_profile: String,

    /// dump SpecCharacters (JSON par ligne)
    #[arg(long)]
    pub spec_json: bool,

    /// force la génération du hint ASCII
    #[arg(long)]
    pub ascii_hint: bool,

    /// résout les enregistrements MX du domaine (feature `with-mx`)
    #[cfg(feature = "with-mx")]
    #[arg(long)]
    pub mx: bool,

    /// teste la délivrabilité SMTP (feature `with-smtp-verify`)
    #[cfg(feature = "with-smtp-verify")]
    #[arg(long)]
    pub deliverability: bool,

    /// vérifie les enregistrements SPF/DKIM/DMARC (feature `with-auth-records`)
    #[cfg(feature = "with-auth-records")]
    #[arg(long)]
    pub auth: bool,

    /// ajoute un sélecteur DKIM à interroger (répétable)
    #[cfg(feature = "with-auth-records")]
    #[arg(long = "dkim-selector")]
    pub dkim_selectors: Vec<String>,

    /// ignore l'enregistrement de politique DKIM (_domainkey)
    #[cfg(feature = "with-auth-records")]
    #[arg(long)]
    pub skip_dkim_policy: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Validate {
        /// mode: strict|relaxed (prend le pas sur l'option globale)
        #[arg(long)]
        mode: Option<String>,
        email: String,
    },
    #[cfg(feature = "with-smtp-verify")]
    #[command(name = "verify-exists")]
    VerifyExists {
        /// adresse e-mail à tester
        email: String,
        /// format de sortie (human|json)
        #[arg(long, default_value = "human")]
        format: String,
        /// nom utilisé pour EHLO/HELO
        #[arg(long)]
        helo: Option<String>,
        /// enveloppe MAIL FROM (par défaut postmaster@domaine)
        #[arg(long = "from")]
        mail_from: Option<String>,
        /// requiert STARTTLS si proposé
        #[arg(long = "require-starttls")]
        require_starttls: bool,
        /// nombre d'adresses aléatoires pour détecter un catch-all
        #[arg(long = "catchall-probes", default_value_t = 1)]
        catchall_probes: u8,
        /// nombre maximum d'MX interrogés
        #[arg(long = "max-mx", default_value_t = 3)]
        max_mx: usize,
        /// timeout global (ms)
        #[arg(long = "timeout", default_value_t = 5_000)]
        timeout_ms: u64,
        /// autorise IPv6
        #[arg(long = "ipv6")]
        ipv6: bool,
    },
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn clap_command() -> clap::Command {
        <Self as clap::CommandFactory>::command()
    }

    pub fn parsed_mode(&self) -> ValidationMode {
        mode_from_str(&self.mode)
    }

    pub fn spec_requested(&self) -> bool {
        self.spec_chars || self.spec_json || self.ascii_hint
    }
}

pub fn mode_from_str(s: &str) -> ValidationMode {
    match s {
        "relaxed" => ValidationMode::Relaxed,
        _ => ValidationMode::Strict,
    }
}

pub fn spec_options_from_profile(profile: &str) -> Result<SpecOptions> {
    match profile {
        "standard" => Ok(SpecOptions::standard()),
        "strict" => Ok(SpecOptions::strict()),
        "fr-fraud" => Ok(SpecOptions::fr_fraud()),
        other => bail!("unknown --spec-profile '{other}'"),
    }
}
