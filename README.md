# mailcheck_lib

Bibliothèque et CLI en Rust pour vérifier et normaliser des adresses e‑mail.  
Ce projet fournit :

- une API (`mailcheck_lib`) pour valider un e‑mail, produire une version normalisée (domaine en ASCII/IDNA) et détecter les caractères spéciaux susceptibles d’induire en erreur ;
- une fonction `check_mx` (feature `with-mx`) pour résoudre les enregistrements MX d’un domaine ;
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

Commandes
    validate [--mode <...>] <EMAIL>
                                Valide une adresse unique (prioritaire sur --mode global)
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
| `mx`               | Résultat MX (`status`, `error` ou `skipped`) quand `--mx` est activé         |

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

## Contribution

1. Fork / branche (`feat/...`).
2. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`.
3. Préparer un PR avec un résumé clair et des exemples (ajouter des tests si possible).

## Licence

MIT ou Apache-2.0 (double licence). Voir `Cargo.toml`.
