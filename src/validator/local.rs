/// Règles strictes: atext ASCII + '.' non initial/terminal, pas de ".."
pub(crate) fn is_local_strict(s: &str) -> bool {
    if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '/'
                    | '='
                    | '?'
                    | '^'
                    | '_'
                    | '`'
                    | '{'
                    | '|'
                    | '}'
                    | '~'
                    | '.'
            )
    })
}

/// Règles relaxed: autorise une quoted-string simple,
/// sinon retombe sur `is_local_strict`.
pub(crate) fn is_local_relaxed(s: &str) -> bool {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        true
    } else {
        is_local_strict(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_dots() {
        assert!(!is_local_strict(".abc"));
        assert!(!is_local_strict("abc."));
        assert!(!is_local_strict("a..b"));
        assert!(is_local_strict("a.b"));
    }
    #[test]
    fn relaxed_quoted() {
        assert!(is_local_relaxed("\"a b\""));
    }
}
