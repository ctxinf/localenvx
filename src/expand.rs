//! dotenv-expand 12 semantics over the final environment, in insertion order.
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

/// Find the outermost reference so an unused conditional branch stays unevaluated.
fn reference(text: &str, from: usize) -> Option<(usize, usize, &str)> {
    for (offset, ch) in text[from..].char_indices() {
        let start = from + offset;
        if ch != '$' || (start > 0 && text.as_bytes()[start - 1] == b'\\') {
            continue;
        }
        let rest = &text[start + 1..];
        if let Some(braced) = rest.strip_prefix('{') {
            let mut depth = 1;
            for (end, ch) in braced.char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    if end > 0 {
                        return Some((start, start + end + 3, &braced[..end]));
                    }
                    break;
                }
            }
        } else if rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            let len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            return Some((start, start + len + 1, &rest[..len]));
        }
    }
    None
}

fn expression(expression: &str) -> (&str, &str, &str) {
    for (i, ch) in expression.char_indices() {
        if ch == ':' {
            if expression[i..].starts_with(":+") || expression[i..].starts_with(":-") {
                return (
                    &expression[..i],
                    &expression[i..i + 2],
                    &expression[i + 2..],
                );
            }
        } else if matches!(ch, '+' | '-') {
            return (
                &expression[..i],
                &expression[i..i + 1],
                &expression[i + 1..],
            );
        }
    }
    (expression, "", "")
}

fn replacement_text(replacement: &str, input: &str, start: usize, end: usize) -> String {
    let mut out = String::new();
    let mut chars = replacement.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            match chars.peek() {
                Some('$') => {
                    chars.next();
                    out.push('$');
                    continue;
                }
                Some('&') => {
                    chars.next();
                    out.push_str(&input[start..end]);
                    continue;
                }
                Some('`') => {
                    chars.next();
                    out.push_str(&input[..start]);
                    continue;
                }
                Some('\'') => {
                    chars.next();
                    out.push_str(&input[end..]);
                    continue;
                }
                _ => {}
            }
        }
        out.push(ch);
    }
    out
}

/// Resolve raw values only when expansion actually reads them. Keys replaced by
/// temporary variables are not roots, but remain available as dependencies.
pub fn expand_with(
    entries: &mut [(String, Zeroizing<String>)],
    replaced: &HashSet<String>,
    mut resolve: impl FnMut(&str, &str) -> Result<Zeroizing<String>>,
) -> Result<()> {
    // Integer property names come first in JavaScript's object enumeration.
    let mut order: Vec<usize> = (0..entries.len()).collect();
    let index = |key: &str| {
        key.parse::<u32>()
            .ok()
            .filter(|n| *n != u32::MAX && n.to_string() == key)
    };
    order.sort_by_key(|i| (index(&entries[*i].0).is_none(), index(&entries[*i].0)));
    let mut env: HashMap<String, Zeroizing<String>> = entries.iter().cloned().collect();
    let mut running: HashMap<String, Zeroizing<String>> = HashMap::new();
    let mut resolved = HashSet::new();
    for i in order {
        if replaced.contains(&entries[i].0) {
            continue;
        }
        let mut result = resolve_value(&entries[i].0, &mut env, &mut resolved, &mut resolve)?;
        let mut seen = HashSet::new();
        while let Some((start, end, expr)) = reference(&result, 0) {
            let (key, op, default) = expression(expr);
            let key = key.to_string();
            let value = resolve_value(&key, &mut env, &mut resolved, &mut resolve)?;
            let value = value.as_str();
            let fallback = if matches!(op, "+" | ":+") && value.is_empty() {
                ""
            } else {
                default
            };
            let replacement = if matches!(op, "+" | ":+")
                || value.is_empty()
                || seen.contains(value)
                || value == result.as_str()
            {
                fallback
            } else {
                value
            };
            seen.insert(result.to_string());
            let mut next = Zeroizing::new(String::with_capacity(result.len() + replacement.len()));
            next.push_str(&result[..start]);
            next.push_str(&replacement_text(replacement, &result, start, end));
            next.push_str(&result[end..]);
            // Replacement-string metacharacters can make upstream loop forever.
            if seen.contains(next.as_str()) {
                result = next;
                break;
            }
            result = next;
            if env.get(&key).is_some_and(|s| **s == *result)
                && running.get(&key).is_some_and(|s| **s == *result)
            {
                break;
            }
        }
        // Resolve escaped dollars once, after expansion of each environment entry.
        result = Zeroizing::new(result.replace("\\$", "$"));
        running.insert(entries[i].0.clone(), result.clone());
        env.insert(entries[i].0.clone(), result.clone());
        entries[i].1 = result;
    }
    Ok(())
}

fn resolve_value(
    key: &str,
    env: &mut HashMap<String, Zeroizing<String>>,
    resolved: &mut HashSet<String>,
    resolve: &mut impl FnMut(&str, &str) -> Result<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let Some(value) = env.get(key) else {
        return Ok(Zeroizing::new(String::new()));
    };
    if !resolved.contains(key) {
        let value = resolve(key, value)?;
        env.insert(key.to_string(), value);
        resolved.insert(key.to_string());
    }
    Ok(env[key].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values(entries: &[(&str, &str)]) -> Vec<(String, Zeroizing<String>)> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }
    fn expand(entries: &mut [(String, Zeroizing<String>)]) {
        expand_with(entries, &HashSet::new(), |_, value| {
            Ok(Zeroizing::new(value.to_string()))
        })
        .unwrap();
    }

    #[test]
    fn matches_pinned_dotenv_expand_oracle() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/expand-v12.json")).unwrap();
        assert!(cases.as_array().unwrap().len() >= 15);
        for case in cases.as_array().unwrap() {
            let mut entries: Vec<_> = case["input"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    (
                        pair[0].as_str().unwrap().to_string(),
                        Zeroizing::new(pair[1].as_str().unwrap().to_string()),
                    )
                })
                .collect();
            expand(&mut entries);
            let actual: Vec<_> = entries.iter().map(|(_, value)| value.as_str()).collect();
            let expected: Vec<_> = case["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            assert_eq!(actual, expected, "input: {}", case["input"]);
        }
    }

    #[test]
    fn references_defaults_escapes_and_cycles() {
        let mut entries = values(&[
            ("A", "hello"),
            ("B", "$A/${MISSING:-world}"),
            ("C", "${A:+yes}-${MISSING+no}"),
            ("D", "\\$A"),
            ("SELF", "$SELF"),
            ("X", "$Y"),
            ("Y", "$X"),
        ]);
        expand(&mut entries);
        let values: Vec<_> = entries.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(values, ["hello", "hello/world", "yes-", "$A", "", "", ""]);
    }
    #[test]
    fn nested_defaults_and_forward_references() {
        let mut entries = values(&[
            ("A", "${ABSENT:-${B:-fallback}}"),
            ("B", "future"),
            ("C", "${EMPTY-default}"),
            ("EMPTY", ""),
        ]);
        expand(&mut entries);
        assert_eq!(&*entries[0].1, "future");
        assert_eq!(&*entries[2].1, "default");
    }
}
