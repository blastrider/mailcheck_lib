use std::borrow::Cow;
use std::collections::HashSet;

use phf::phf_map;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use unicode_script::{Script, UnicodeScript};

use super::types::{SpecCharacters, SpecClass, SpecFinding, SpecOptions, SpecSegment};

const DIACRITIC_MAP: phf::Map<char, &'static str> = phf_map! {
    'à' => "a", 'á' => "a", 'â' => "a", 'ä' => "a", 'ã' => "a", 'å' => "a",
    'À' => "A", 'Á' => "A", 'Â' => "A", 'Ä' => "A", 'Ã' => "A", 'Å' => "A",
    'ç' => "c", 'Ç' => "C",
    'è' => "e", 'é' => "e", 'ê' => "e", 'ë' => "e",
    'È' => "E", 'É' => "E", 'Ê' => "E", 'Ë' => "E",
    'ì' => "i", 'í' => "i", 'î' => "i", 'ï' => "i",
    'Ì' => "I", 'Í' => "I", 'Î' => "I", 'Ï' => "I",
    'ñ' => "n", 'Ñ' => "N",
    'ò' => "o", 'ó' => "o", 'ô' => "o", 'ö' => "o", 'õ' => "o",
    'Ò' => "O", 'Ó' => "O", 'Ô' => "O", 'Ö' => "O", 'Õ' => "O",
    'ù' => "u", 'ú' => "u", 'û' => "u", 'ü' => "u",
    'Ù' => "U", 'Ú' => "U", 'Û' => "U", 'Ü' => "U",
    'ÿ' => "y", 'Ÿ' => "Y",
    'œ' => "oe", 'Œ' => "OE",
    'æ' => "ae", 'Æ' => "AE",
};

const FR_HINT_EXTRA_MAP: phf::Map<char, &'static str> = phf_map! {
    '«' => "\"",
    '»' => "\"",
    '“' => "\"",
    '”' => "\"",
    '‘' => "'",
    '’' => "'",
    '–' => "-",
    '—' => "-",
    '‑' => "-",
};

const CONFUSABLE_MAP: phf::Map<char, &'static str> = phf_map! {
    // Cyrillic
    'а' => "a",
    'А' => "A",
    'е' => "e",
    'Е' => "E",
    'о' => "o",
    'О' => "O",
    'р' => "p",
    'Р' => "P",
    'с' => "c",
    'С' => "C",
    'у' => "y",
    'У' => "Y",
    'х' => "x",
    'Х' => "X",
    // Greek (upper case focus)
    'Α' => "A",
    'Β' => "B",
    'Ε' => "E",
    'Η' => "H",
    'Ι' => "I",
    'Κ' => "K",
    'Μ' => "M",
    'Ν' => "N",
    'Ο' => "O",
    'Ρ' => "P",
    'Τ' => "T",
    'Χ' => "X",
    'Υ' => "Y",
};

#[derive(Default)]
struct SegmentResult {
    confusable: bool,
    mixed_scripts: bool,
}

#[derive(Default)]
pub(crate) struct SpecComputation {
    pub characters: SpecCharacters,
    pub confusable_labels_for_policy: Vec<String>,
    pub mixed_labels_for_policy: Vec<String>,
}

pub(crate) fn analyze_spec_characters(
    local: &str,
    domain: &str,
    options: &SpecOptions,
) -> SpecComputation {
    let mut computation = SpecComputation {
        characters: SpecCharacters::default(),
        confusable_labels_for_policy: Vec::new(),
        mixed_labels_for_policy: Vec::new(),
    };

    let allowlist: HashSet<String> = options
        .allowlist_labels
        .iter()
        .map(|label| label.to_ascii_lowercase())
        .collect();

    let mut ascii_local = if options.ascii_hint {
        Some(String::new())
    } else {
        None
    };
    let mut ascii_domain = if options.ascii_hint {
        Some(String::new())
    } else {
        None
    };

    // Local-part
    if let Some(ref mut buf) = ascii_local {
        process_segment(
            SpecSegment::Local,
            local,
            options,
            Some(buf),
            &mut computation.characters,
        );
    } else {
        process_segment(
            SpecSegment::Local,
            local,
            options,
            None,
            &mut computation.characters,
        );
    }

    // Domain labels
    if !domain.is_empty() {
        for label in domain.split('.') {
            let label_segment = SpecSegment::Label(label.to_string());
            let result = if let Some(ref mut buf) = ascii_domain {
                if !buf.is_empty() {
                    buf.push('.');
                }
                process_segment(
                    label_segment.clone(),
                    label,
                    options,
                    Some(buf),
                    &mut computation.characters,
                )
            } else {
                process_segment(
                    label_segment.clone(),
                    label,
                    options,
                    None,
                    &mut computation.characters,
                )
            };

            let label_lower = label.to_ascii_lowercase();
            let allowlisted = allowlist.contains(&label_lower);
            if result.confusable
                && !allowlisted
                && !computation
                    .confusable_labels_for_policy
                    .iter()
                    .any(|l| l == &label_lower)
            {
                computation
                    .confusable_labels_for_policy
                    .push(label_lower.clone());
            }
            if result.mixed_scripts
                && !allowlisted
                && !computation
                    .mixed_labels_for_policy
                    .iter()
                    .any(|l| l == &label_lower)
            {
                computation
                    .mixed_labels_for_policy
                    .push(label_lower.clone());
            }
        }
    }

    if let Some(ref mut dom_hint) = ascii_domain {
        dom_hint.make_ascii_lowercase();
    }

    if options.ascii_hint {
        let hint = match (ascii_local, ascii_domain) {
            (Some(local_hint), Some(domain_hint)) if !domain_hint.is_empty() => {
                Some(format!("{local_hint}@{domain_hint}"))
            }
            (Some(local_hint), Some(_)) if domain.is_empty() => Some(local_hint),
            (Some(local_hint), None) if !domain.is_empty() => {
                Some(format!("{local_hint}@{}", domain.to_ascii_lowercase()))
            }
            (Some(local_hint), None) => Some(local_hint),
            (None, Some(domain_hint)) if !domain_hint.is_empty() => {
                if local.is_empty() {
                    Some(domain_hint)
                } else {
                    Some(format!("{}@{domain_hint}", local))
                }
            }
            _ => None,
        };
        computation.characters.normalized_ascii_hint = hint;
    }

    computation
}

impl SpecComputation {
    pub(crate) fn apply_policy(
        &self,
        options: &SpecOptions,
        domain: &str,
        reasons: &mut Vec<String>,
    ) {
        let domain_lower = domain.to_ascii_lowercase();

        if let Some(reason) = &options.domain_confusable_reason {
            if !self.confusable_labels_for_policy.is_empty() && !reasons.iter().any(|r| r == reason)
            {
                reasons.push(reason.clone());
            }
        }

        if !self.confusable_labels_for_policy.is_empty() {
            for (tld, warning) in &options.confusable_tld_warnings {
                if domain_matches_tld(&domain_lower, tld) && !reasons.iter().any(|r| r == warning) {
                    reasons.push(warning.clone());
                }
            }
        }

        if let Some(reason) = &options.domain_mixed_scripts_reason {
            if !self.mixed_labels_for_policy.is_empty() && !reasons.iter().any(|r| r == reason) {
                reasons.push(reason.clone());
            }
        }
    }
}

fn domain_matches_tld(domain: &str, tld: &str) -> bool {
    if tld.is_empty() {
        return false;
    }
    if domain == tld {
        return true;
    }
    let needle = format!(".{tld}");
    domain.ends_with(&needle)
}

fn process_segment(
    segment: SpecSegment,
    text: &str,
    options: &SpecOptions,
    mut ascii_buf: Option<&mut String>,
    characters: &mut SpecCharacters,
) -> SegmentResult {
    let mut result = SegmentResult::default();
    let mut primary_script: Option<Script> = None;
    let mut mixed_reported = false;

    for ch in text.chars() {
        let ascii_hint = ascii_hint_for_char(ch, options);

        if let Some(ref mut buf) = ascii_buf {
            if let Some(ref hint) = ascii_hint {
                buf.push_str(hint.as_ref());
            } else {
                buf.push(ch);
            }
        }

        if options.detect_confusables {
            if let Some(repl) = CONFUSABLE_MAP.get(&ch) {
                result.confusable = true;
                characters.has_confusables = true;
                let note = format!("{}({}) → {}(lat)", ch, script_abbrev(ch), repl);
                characters.details.push(SpecFinding {
                    segment: segment.clone(),
                    codepoint: ch,
                    class: SpecClass::Confusable,
                    note,
                });
            }
        }

        if options.detect_diacritics {
            if let Some(repl) = DIACRITIC_MAP.get(&ch) {
                characters.has_diacritics = true;
                let note = format!("{ch} → {repl} (diacritic)");
                characters.details.push(SpecFinding {
                    segment: segment.clone(),
                    codepoint: ch,
                    class: SpecClass::Diacritic,
                    note,
                });
            } else if is_combining_mark(ch) {
                characters.has_diacritics = true;
                let note = format!("U+{:04X} combining mark removed", ch as u32);
                characters.details.push(SpecFinding {
                    segment: segment.clone(),
                    codepoint: ch,
                    class: SpecClass::Diacritic,
                    note,
                });
            }
        }

        if options.detect_mixed_scripts {
            if let Some(script) = major_script(ch) {
                if let Some(primary) = primary_script {
                    if script != primary && !mixed_reported {
                        characters.has_mixed_scripts = true;
                        result.mixed_scripts = true;
                        mixed_reported = true;
                        let note = match &segment {
                            SpecSegment::Local => "mixed scripts in local".to_string(),
                            SpecSegment::Domain => "mixed scripts in domain".to_string(),
                            SpecSegment::Label(label) => {
                                format!("mixed scripts in label '{}'", label)
                            }
                        };
                        characters.details.push(SpecFinding {
                            segment: segment.clone(),
                            codepoint: ch,
                            class: SpecClass::MixedScript,
                            note,
                        });
                    }
                } else {
                    primary_script = Some(script);
                }
            }
        }
    }

    result
}

fn ascii_hint_for_char<'a>(ch: char, options: &SpecOptions) -> Option<Cow<'a, str>> {
    if is_combining_mark(ch) {
        return Some(Cow::Borrowed(""));
    }
    if let Some(repl) = CONFUSABLE_MAP.get(&ch) {
        return Some(Cow::Borrowed(repl));
    }
    if let Some(repl) = DIACRITIC_MAP.get(&ch) {
        return Some(Cow::Borrowed(repl));
    }
    if options.use_fr_hint_extensions {
        if let Some(repl) = FR_HINT_EXTRA_MAP.get(&ch) {
            return Some(Cow::Borrowed(repl));
        }
    }
    if ch.is_ascii() {
        return None;
    }

    let mut decomposed = String::new();
    for d in ch.to_string().nfkd() {
        if !is_combining_mark(d) && d.is_ascii() {
            decomposed.push(d);
        }
    }
    if decomposed.is_empty() {
        None
    } else {
        Some(Cow::Owned(decomposed))
    }
}

fn major_script(ch: char) -> Option<Script> {
    match ch.script() {
        Script::Common | Script::Inherited | Script::Unknown => None,
        script => Some(script),
    }
}

fn script_abbrev(ch: char) -> &'static str {
    match ch.script() {
        Script::Cyrillic => "cyr",
        Script::Greek => "gre",
        Script::Latin => "lat",
        Script::Han => "han",
        Script::Arabic => "ara",
        Script::Hebrew => "heb",
        Script::Hiragana => "hira",
        Script::Katakana => "kata",
        Script::Hangul => "hang",
        _ => "unk",
    }
}

fn segment_label(segment: &SpecSegment) -> String {
    match segment {
        SpecSegment::Local => "Local".to_string(),
        SpecSegment::Domain => "Domain".to_string(),
        SpecSegment::Label(label) => format!("Label({})", label),
    }
}

pub(crate) fn join_spec_notes(details: &[SpecFinding]) -> Option<String> {
    if details.is_empty() {
        None
    } else {
        let joined = details
            .iter()
            .map(|finding| format!("{}: {}", segment_label(&finding.segment), finding.note))
            .collect::<Vec<_>>()
            .join(" | ");
        Some(joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::types::SpecOptions;

    #[test]
    fn detects_local_diacritics() {
        let opts = SpecOptions::standard();
        let result = analyze_spec_characters("péché", "example.com", &opts);
        let spec = result.characters;
        assert!(spec.has_diacritics);
        assert_eq!(
            spec.normalized_ascii_hint.as_deref(),
            Some("peche@example.com")
        );
        let notes = join_spec_notes(&spec.details).unwrap();
        assert!(notes.contains("Local:"));
        assert!(notes.contains("é → e"));
    }

    #[test]
    fn detects_domain_diacritics() {
        let opts = SpecOptions::standard();
        let result = analyze_spec_characters("user", "exämple.com", &opts);
        let spec = result.characters;
        assert!(spec.has_diacritics);
        let notes = join_spec_notes(&spec.details).unwrap();
        assert!(notes.contains("Label(exämple)"));
        assert!(notes.contains("ä → a"));
    }

    #[test]
    fn detects_confusable_local() {
        let opts = SpecOptions::standard();
        let confusable_local = "usеr"; // 'е' cyrillique
        let result = analyze_spec_characters(confusable_local, "example.com", &opts);
        let spec = result.characters;
        assert!(spec.has_confusables);
        assert!(
            spec.details
                .iter()
                .any(|f| matches!(f.class, SpecClass::Confusable))
        );
    }

    #[test]
    fn detects_mixed_scripts_in_label() {
        let opts = SpecOptions::standard();
        let result = analyze_spec_characters("user", "exаmple.com", &opts); // 'а' cyrillique
        let spec = result.characters;
        assert!(spec.has_mixed_scripts);
        let notes = join_spec_notes(&spec.details).unwrap();
        assert!(notes.contains("mixed scripts"));
    }

    #[test]
    fn punycode_domain_is_neutral() {
        let opts = SpecOptions::standard();
        let result = analyze_spec_characters("user", "xn--exmple-cua.com", &opts);
        let spec = result.characters;
        assert!(!spec.has_diacritics);
        assert!(!spec.has_confusables);
        assert!(spec.details.is_empty());
    }
}
