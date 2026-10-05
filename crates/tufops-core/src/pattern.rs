//! Comparing the patterns of delegated paths. Patterns match target paths the way rust-tuf's
//! `PathPattern` does: component by component, where `*` matches any characters and `?` any one
//! character, but neither matches a `/`.

/// Whether some path matches both `first` and `second`.
pub fn overlap(first: &str, second: &str) -> bool {
    by_component(first, second, component_overlap)
}

/// Whether every path that matches `specific` also matches `general`. This is decided by matching
/// `general` against `specific` as if it were a path, in which a `?` can only be matched by a `?`
/// or `*`, and a `*` only by a `*`. That covers the ways one pattern narrows another, like
/// `fw/*.bin` and `fw/beta-*.bin`, but misses some contrived ones: `?*` and `*?` both match every
/// non-empty component, yet neither is found to contain the other.
pub fn contains(general: &str, specific: &str) -> bool {
    by_component(general, specific, component_contains)
}

/// Whether `first` and `second` have as many components, and `compare` holds for each pair.
fn by_component(first: &str, second: &str, compare: fn(&[char], &[char]) -> bool) -> bool {
    let components = |pattern: &str| -> Vec<Vec<char>> {
        let split = pattern.split('/');
        split.map(|component| component.chars().collect()).collect()
    };
    let (first, second) = (components(first), components(second));
    first.len() == second.len()
        && (first.iter().zip(&second)).all(|(first, second)| compare(first, second))
}

/// Whether some string matches both components `first` and `second`.
fn component_overlap(first: &[char], second: &[char]) -> bool {
    // Whether some string matches both `first[..first_len]` and `second[..second_len]`.
    let mut matched = vec![vec![false; second.len() + 1]; first.len() + 1];
    matched[0][0] = true;
    for first_len in 0..=first.len() {
        for second_len in 0..=second.len() {
            if !matched[first_len][second_len] {
                continue;
            }
            let (first_next, second_next) = (first.get(first_len), second.get(second_len));
            // A `*` matching nothing more.
            if first_next == Some(&'*') {
                matched[first_len + 1][second_len] = true;
            }
            if second_next == Some(&'*') {
                matched[first_len][second_len + 1] = true;
            }
            // Both matching one more character, which a wildcard can be. A `*` stays to match
            // more after it.
            if let (Some(&first_next), Some(&second_next)) = (first_next, second_next) {
                let wildcard = |next| next == '*' || next == '?';
                if first_next == second_next || wildcard(first_next) || wildcard(second_next) {
                    let first_len = first_len + usize::from(first_next != '*');
                    let second_len = second_len + usize::from(second_next != '*');
                    matched[first_len][second_len] = true;
                }
            }
        }
    }
    matched[first.len()][second.len()]
}

/// Whether component `general` matches component `specific` as if it were a string, in which a
/// `?` can only be matched by a `?` or `*`, and a `*` only by a `*`.
fn component_contains(general: &[char], specific: &[char]) -> bool {
    // Whether `general[..general_len]` matches `specific[..specific_len]`.
    let mut matched = vec![vec![false; specific.len() + 1]; general.len() + 1];
    matched[0][0] = true;
    for general_len in 0..=general.len() {
        for specific_len in 0..=specific.len() {
            if !matched[general_len][specific_len] {
                continue;
            }
            let specific_next = specific.get(specific_len).copied();
            match general.get(general_len) {
                // A `*` matching nothing more, or one more character, staying to match more.
                Some('*') => {
                    matched[general_len + 1][specific_len] = true;
                    if specific_next.is_some() {
                        matched[general_len][specific_len + 1] = true;
                    }
                }
                Some(&'?') if specific_next.is_some_and(|next| next != '*') => {
                    matched[general_len + 1][specific_len + 1] = true;
                }
                Some(&next) if specific_next == Some(next) => {
                    matched[general_len + 1][specific_len + 1] = true;
                }
                _ => {}
            }
        }
    }
    matched[general.len()][specific.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping() {
        let overlapping = [
            ("fw/a.bin", "fw/a.bin"),
            ("fw/*", "fw/a.bin"),
            ("fw/*.bin", "fw/beta-*"),
            ("*/a.bin", "fw/*"),
            ("*a*", "*b*"),
            ("a?c", "?b?"),
            ("?", "*"),
            ("fw/*", "fw/"),
        ];
        for (first, second) in overlapping {
            assert!(overlap(first, second), "{first} and {second} overlap");
            assert!(overlap(second, first), "{second} and {first} overlap");
        }
        let separate = [
            ("fw/a.bin", "fw/b.bin"),
            ("fw/*", "fw/*/*"),
            ("fw/*", "bin/*"),
            ("*.bin", "*.txt"),
            ("ab", "*c*"),
            ("a?", "b*"),
            ("?", "??"),
            ("fw/?", "fw/"),
        ];
        for (first, second) in separate {
            assert!(!overlap(first, second), "{first} and {second} are separate");
            assert!(!overlap(second, first), "{second} and {first} are separate");
        }
    }

    #[test]
    fn containing() {
        let containing = [
            ("fw/a.bin", "fw/a.bin"),
            ("fw/*", "fw/a.bin"),
            ("fw/*", "fw/beta-*"),
            ("fw/*.bin", "fw/beta-*.bin"),
            ("*/*", "fw/*"),
            ("fw/?.bin", "fw/a.bin"),
            ("fw/*", "fw/?"),
            ("??", "a?"),
            ("*", "**"),
            ("**", "*"),
        ];
        for (general, specific) in containing {
            assert!(contains(general, specific), "{general} contains {specific}");
        }
        let not_containing = [
            ("fw/a.bin", "fw/*"),
            ("fw/beta-*", "fw/*"),
            ("fw/*", "fw/*/*"),
            ("fw/*.bin", "fw/beta-*"),
            ("?", "*"),
            ("a?", "??"),
            ("*a", "a*"),
        ];
        for (general, specific) in not_containing {
            assert!(
                !contains(general, specific),
                "{general} doesn't contain {specific}"
            );
        }
    }
}
