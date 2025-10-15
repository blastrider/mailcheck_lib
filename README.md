# mailcheck_lib

Bibliothèque et CLI en Rust pour vérifier et normaliser des adresses e‑mail.  
Ce projet fournit :

- une API (`mailcheck_lib`) pour valider un e‑mail, produire une version normalisée (domaine en ASCII/IDNA) et détecter les caractères spéciaux susceptibles d’induire en erreur ;
- une fonction `check_mx` (feature `with-mx`) pour résoudre les enregistrements MX d’un domaine ;
 - une fonction `check_mailaddress_exists` (feature `with-smtp-verify`) pour sonder la délivrabilité SMTP sans envoyer de message ;
- une fonction `check_auth_records` (feature `with-auth-records`) pour auditer SPF, DKIM et DMARC ;
- un binaire `mailcheck-cli` pour traiter des adresses depuis la ligne de commande, des fichiers ou des flux (`stdin`).

## Compilation

```bash
cargo build --release
```

Le binaire est disponible dans `target/release/mailcheck-cli`.  
Pour exécuter l’ensemble des tests et lints utilisés dans CI :

```bash
make ci
# ou
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## mailcheck-cli – guide d’utilisation

```
mailcheck-cli [OPTIONS] [COMMAND]

Options générales
    --stdin                     Lit une adresse par ligne sur stdin
    --out <PATH>                Écrit la sortie dans un fichier (selon --format)
    --mode <strict|relaxed>     Mode de validation (défaut strict)
    --format <human|json|ndjson|csv>
                                Forme de la sortie (défaut human)

Options de détection de caractères spéciaux (spéculation typosquatting)
    --spec-chars                Active l’analyse des caractères spéciaux
    --spec-profile <standard|strict|fr-fraud>
                                Choix du profil de détection (défaut standard)
    --spec-json                 Affiche le bloc SpecCharacters (JSON par ligne)
    --ascii-hint                Force la génération d’un hint ASCII (même sans spec-chars)
    --mx                        Résout les enregistrements MX (feature with-mx)
    --deliverability            Teste la délivrabilité SMTP (feature with-smtp-verify)
    --auth                      Vérifie SPF/DKIM/DMARC (feature with-auth-records)
    --dkim-selector <NAME>      Ajoute un sélecteur DKIM (répéter l’option)
    --skip-dkim-policy          Ignore l’enregistrement _domainkey (feature with-auth-records)

Commandes
    validate [--mode <...>] <EMAIL>
                                Valide une adresse unique (prioritaire sur --mode global)
    verify-exists <EMAIL> [options]
                                Vérifie l'existence via SMTP (feature with-smtp-verify)
```

### Modes de validation

- `strict` (défaut) : règles RFC plus conservatrices (local-part ASCII limité).
- `relaxed` : autorise les `quoted-string` minimalement.

### Formats de sortie

- `human` : affichage simple ; `[OK]` ou `[INVALID]`, suivi de l’adresse et des raisons éventuelles.
- `json` : sérialise le tableau de résultats (requiert la feature `with-serde`).
- `ndjson` : une ligne JSON par adresse (feature `with-serde`).
- `csv` : colonnes stables (feature `with-csv`).  
  Ajoute, lorsque `--spec-chars` est actif, les colonnes
  `has_confusables`, `has_diacritics`, `has_mixed_scripts`, `spec_notes`, `ascii_hint`.
  Avec `--mx`, deux colonnes supplémentaires (`mx_status`, `mx_detail`) décrivent
  la résolution MX.
  Avec `--deliverability`, deux colonnes (`deliverability_status`, `deliverability_detail`)
  résument le test SMTP (délivrable, rejet, refus temporaire…).
  Avec `--auth`, six colonnes (`auth_spf`, `auth_dmarc`, `auth_dkim_policy`,
  `auth_selectors`, `auth_error`, `auth_skipped`) exposent le résumé des politiques publiées.

### Analyse de caractères spéciaux (`--spec-chars`)

Active la détection :

- **Diacritiques** : lettres accentuées (ex. `é`, `ä`), reportées avec leur translittération (`é → e`).
- **Confusables** : homoglyphes inter-scripts (`а` cyrillique vs `a` latin, majuscules grecques, etc.).
- **Mix de scripts** : segments mélangeant plusieurs scripts (Latin + Cyrillic…).

Les résultats sont exposés via :

- `spec_chars` : bloc détaillé (JSON) avec la liste des findings par segment (Local, Domain, Label).
- Champs récapitulatifs sur chaque enregistrement : `has_confusables`, `has_diacritics`, `has_mixed_scripts`, `spec_notes` (concat segment:note), `ascii_hint`.

#### Profils disponibles (`--spec-profile`)

- `standard` : toutes les détections actives, hint ASCII généré par défaut.
- `strict` : identique au standard + ajoute un `reason` si des confusables apparaissent dans le domaine.
- `fr-fraud` : profil orienté anti-fraude pour .fr/.gouv.fr
  - translittération étendue (`œ` → `oe`, ligatures, guillemets typographiques).
  - avertissement spécifique si confusables détectés sur un domaine `.fr` ou `.gouv.fr`.
  - `reason` supplémentaire en cas de mix de scripts dans le domaine.

`--ascii-hint` force la génération du hint même si le profil sélectionné le désactive.

### Exemples

```bash
# Valide une adresse
mailcheck-cli validate alice@example.com

# Lit depuis stdin, format NDJSON, avec détection des caractères spéciaux
cat addresses.txt | mailcheck-cli --stdin --format ndjson --spec-chars

# CSV complet avec profil strict et sortie dans un fichier
mailcheck-cli --stdin --format csv --out report.csv \
  --spec-chars --spec-profile strict < addresses.txt

# Voir uniquement le bloc SpecCharacters pour inspection
mailcheck-cli --stdin --spec-chars --spec-json < addresses.txt

# Vérifier l'existence SMTP d'une adresse précise
mailcheck-cli verify-exists alice@example.com --timeout 7000 --format human
```

### Champs renvoyés (formats structurés)

| Champ              | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `original`         | Adresse en entrée (trimée)                                                   |
| `local`            | Local-part tel qu’extrait                                                    |
| `domain`           | Domaine en minuscules                                                        |
| `ascii_domain`     | Domaine converti en ASCII (IDNA)                                             |
| `mode`             | `strict` ou `relaxed`                                                        |
| `valid`            | Bool indiquant si l’adresse passe la validation                             |
| `reasons`          | Liste des raisons d’invalidation                                             |
| `spec_chars`       | Bloc détaillé (Option) avec findings par caractère                            |
| `has_*`            | Récap booléen (Option) selon les dettes detectées                           |
| `spec_notes`       | Concat `segment:note` (Ordre stable)                                         |
| `ascii_hint`       | Suggestion ASCII lisible (`Option<String>`)                                  |
| `auth`             | Résumé SPF/DKIM/DMARC (`null` si non demandé)                                |
| `mx`               | Résultat MX (`status`, `error` ou `skipped`) quand `--mx` est activé         |
| `deliverability`   | Résultat du test SMTP (`verification`, `error` ou `skipped`)                 |

### Utilisation depuis la bibliothèque

```rust
use mailcheck_lib::{normalize_email_with_spec, SpecOptions, ValidationMode};

let report = normalize_email_with_spec(
    "péché@exämple.com",
    ValidationMode::Strict,
    Some(SpecOptions::standard()),
)?;

assert_eq!(report.valid, false);
assert_eq!(report.ascii_hint.as_deref(), Some("peche@example.com"));
```

Les fonctions principales :

- `validate_email(email, mode)` : validation simple sans détection spéciaux.
- `validate_email_with_spec(email, mode, opts)` : validation + analyse spéciaux.
- `normalize_email(email, mode)` : version normalisée de l’adresse.
- `normalize_email_with_spec(email, mode, opts)` : normalisation + analyse spéciaux.

### Résolution MX (`with-mx`)

Activez la feature `with-mx` pour exposer `check_mx(domain: &str)` et l’option
CLI `--mx`. La fonction renvoie un `MxStatus` :

- `MxStatus::Records(Vec<MxRecord>)` si des enregistrements MX sont trouvés (triés par priorité).
- `MxStatus::NoRecords` si aucun MX n’est publié.

Exemple :

```rust
use mailcheck_lib::{check_mx, MxStatus};

match check_mx("example.com")? {
    MxStatus::Records(records) => println!("{} serveurs MX", records.len()),
    MxStatus::NoRecords => println!("pas de MX déclarés"),
}
```

Depuis le CLI :

```bash
cargo run --features with-mx -- --stdin --mx < domains.txt
```

Les sorties `json`/`ndjson` ajoutent un champ `mx` (contenant `status`, `error`
ou `skipped`). Le CSV expose deux colonnes (`mx_status`, `mx_detail`) quand
`--mx` est présent.

### Délivrabilité SMTP (`with-smtp-verify`)

Activez la feature `with-smtp-verify` pour établir une véritable session SMTP
(`EHLO` → `STARTTLS` si disponible → `MAIL FROM` → `RCPT TO`) et classifier la
réponse en [`Existence`]. La fonction principale est
`check_mailaddress_exists(addr, options)` où `options` est un
[`SmtpProbeOptions`] configurable (MX maximum, timeout, enveloppe, STARTTLS,
tests catch-all…). Le rapport [`SmtpProbeReport`] fournit le verdict, le score
de confiance et la transcription complète.

Exemple :

```rust
use mailcheck_lib::{check_mailaddress_exists, Existence, SmtpProbeOptions};

let options = SmtpProbeOptions {
    catchall_probes: 2,
    helo_domain: "example.com".into(),
    ..SmtpProbeOptions::default()
};

let report = check_mailaddress_exists("alice@example.com", &options)?;

match report.result {
    Existence::Exists => println!("adresse acceptée"),
    Existence::DoesNotExist => println!("n'existe pas"),
    Existence::CatchAll => println!("catch-all probable"),
    Existence::Indeterminate(reason) => println!("inconclu ({reason})"),
}
```

Depuis la CLI :

```bash
# résumé par adresse (option --deliverability)
cargo run --features with-smtp-verify -- --stdin --deliverability < emails.txt

# diagnostic complet
cargo run --features with-smtp-verify -- verify-exists alice@example.com --format human
```

Le champ `deliverability` est ajouté aux formats `human`/`json`/`ndjson` des
rapports par adresse. En CSV, les colonnes `deliverability_status` /
`deliverability_detail` condensent le verdict (`exists`, `does_not_exist`,
`catch_all`, `indeterminate`) et la première preuve SMTP.

### Vérification SPF / DKIM / DMARC (`with-auth-records`)

Activez la feature `with-auth-records` pour interroger les enregistrements TXT pertinents
et obtenir un état synthétique :

- SPF — détecte l’absence de politique, les redirections, les enregistrements multiples ou une politique trop permissive (`SpfStatus`).
- DMARC — vérifie la présence d’un enregistrement valide, identifie les politiques faibles (`none`, `quarantine`) et signale les cas invalides (`DmarcStatus`).
- DKIM — inspecte le _policy record_ (`_domainkey`) et une liste de sélecteurs fournis (`AuthLookupOptions`), en mettant en avant les clés de test ou les anomalies détectées (`DkimStatus`).

#### Depuis la CLI

Compilez le binaire avec la feature :

```bash
cargo run --features "with-auth-records" -- --stdin --auth < domains.txt
```

Ajoutez autant de sélecteurs DKIM que nécessaire :

```bash
cargo run --features "with-auth-records" -- \
  --stdin --auth \
  --dkim-selector default \
  --dkim-selector transactionnel \
  < domains.txt
```

`--auth` enrichit les sorties `human`, `json`, `ndjson` et `csv` avec un bloc `auth`
(`spf`, `dmarc`, `dkim_policy`, `selectors`, erreurs ou raisons de skip). Utilisez
`--skip-dkim-policy` si vous voulez ignorer l’enregistrement `_domainkey`.

```rust
use mailcheck_lib::{
    AuthLookupOptions,
    SpfStatus,
    check_auth_records_with_options,
};

let options = AuthLookupOptions::new()
    .with_dkim_selector("default")
    .with_dkim_selector("transactional");

let status = check_auth_records_with_options("example.com", &options)?;

match status.spf {
    SpfStatus::Compliant { qualifier, .. } => println!("SPF ok ({qualifier:?})"),
    other => println!("SPF à examiner: {other:?}"),
}

println!("DMARC: {:?}", status.dmarc);
println!("DKIM policy: {:?}", status.dkim.policy);
println!("DKIM selectors: {:?}", status.dkim.selectors);
```

La fonction `check_auth_records` utilise les options par défaut (pas de sélecteurs supplémentaires). Chaque statut est sérialisable (`Debug`) pour inspection et peut être converti en reporting applicatif.

## Contribution

1. Fork / branche (`feat/...`).
2. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`.
3. Préparer un PR avec un résumé clair et des exemples (ajouter des tests si possible).

## Licence

MIT ou Apache-2.0 (double licence). Voir `Cargo.toml`.
#### Commande `verify-exists`

Disponible avec `--features with-smtp-verify`, elle déclenche une sonde
individualisée :

```
mailcheck-cli verify-exists <email>
    --helo <nom>               Personnalise EHLO/HELO (défaut: domaine cible)
    --from <adresse>           Envelope MAIL FROM (défaut: postmaster@domaine)
    --require-starttls         Échec si STARTTLS n'est pas annoncé
    --catchall-probes <N>      Nombre d'adresses aléatoires testées (0..=5)
    --max-mx <N>               Limite de serveurs MX interrogés (défaut 3)
    --timeout <ms>             Délai global connexion/lecture (défaut 5000)
    --ipv6                     Autorise les adresses IPv6
    --format <human|json>      Format de sortie (défaut human)
```

La sortie `human` récapitule le verdict, la confiance et les lignes clés du
transcript SMTP. En `json`, l'objet sérialise directement le
[`SmtpProbeReport`].
