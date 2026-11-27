//! Request matching for IAM policy statements.

mod conditions;
pub use conditions::Condition;
pub(crate) use conditions::Operator;

/// Match a request against both target lists of a statement. An empty list
/// matches nothing. Only an asterisk has wildcard meaning.
pub fn matches_target(
    actions: &[String],
    resources: &[String],
    action: &str,
    resource: &str,
) -> bool {
    actions
        .iter()
        .any(|pattern| matches_pattern(pattern, action))
        && resources
            .iter()
            .any(|pattern| matches_pattern(pattern, resource))
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    let Some((prefix, rest)) = pattern.split_once('*') else {
        return value == pattern;
    };
    let Some(remaining) = value.strip_prefix(prefix) else {
        return false;
    };
    let (middle, suffix) = rest.rsplit_once('*').unwrap_or(("", rest));
    let Some(mut remaining) = remaining.strip_suffix(suffix) else {
        return false;
    };

    // Reserve the anchored suffix first. Each intervening literal can take
    // its earliest match, leaving the largest possible tail for later ones.
    for literal in middle.split('*').filter(|part| !part.is_empty()) {
        let Some((_, tail)) = remaining.split_once(literal) else {
            return false;
        };
        remaining = tail;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchored_targets_preserve_literal_characters_and_unicode() {
        for (pattern, value, expected) in [
            ("", "", true),
            ("", "x", false),
            ("*", "", true),
            ("**", "λ/😀", true),
            ("a*a", "a", false),
            ("a*a", "aa", true),
            ("a**b*b", "ab", false),
            ("a*ab*b", "aabbb", true),
            ("*b*a*", "ab", false),
            ("文*😀", "文/本😀", true),
            ("é", "e\u{301}", false),
            ("read?", "reads", false),
            ("[ab]", "a", false),
            ("*?", "a?", true),
            ("read*", "ReadFile", false),
            ("*/doc", "/doc/", false),
        ] {
            assert_eq!(
                matches_pattern(pattern, value),
                expected,
                "{pattern:?} against {value:?}"
            );
        }
    }

    #[test]
    fn both_statement_target_lists_must_match() {
        let actions = vec!["list".into(), "read:*".into()];
        let resources = vec!["accounts/*/files/*".into()];
        assert!(matches_target(
            &actions,
            &resources,
            "read:item",
            "accounts/one/files/1"
        ));
        assert!(!matches_target(
            &actions,
            &resources,
            "read:item",
            "accounts/one"
        ));
        assert!(!matches_target(
            &actions,
            &resources,
            "write:item",
            "accounts/one/files/1"
        ));
        assert!(!matches_target(
            &[],
            &resources,
            "read:item",
            "accounts/one/files/1"
        ));
        assert!(!matches_target(&actions, &[], "list", ""));
    }
}
