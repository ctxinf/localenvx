//! Read-free debug preview using the familiar Node inspect text format.
use std::path::PathBuf;

fn string(value: &str) -> String {
    let quote = if !value.contains('\'') {
        '\''
    } else if !value.contains('"') {
        '"'
    } else if !value.contains('`') && !value.contains("${") {
        '`'
    } else {
        '\''
    };
    let mut result = String::from(quote);
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c == quote => {
                result.push('\\');
                result.push(c);
            }
            c if c.is_control() => result.push_str(&format!("\\x{:02x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push(quote);
    result
}

fn collection(open: char, close: char, items: Vec<String>) -> String {
    if items.is_empty() {
        return format!("{open}{close}");
    }
    let inline = format!("{open} {} {close}", items.join(", "));
    if inline.len() <= 80 {
        inline
    } else {
        format!("{open}\n  {}\n{close}", items.join(",\n  "))
    }
}

pub fn format(paths: &[PathBuf], variables: &[(String, String)]) -> String {
    let paths = collection(
        '[',
        ']',
        paths.iter().map(|p| string(&p.to_string_lossy())).collect(),
    );
    let mut entries: Vec<(String, String)> = Vec::new();
    for (key, value) in variables {
        if let Some(entry) = entries.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.clone();
        } else {
            entries.push((key.clone(), value.clone()));
        }
    }
    // JavaScript object iteration places array-index keys ahead of other keys.
    entries.sort_by_key(|(key, _)| {
        key.parse::<u32>()
            .ok()
            .filter(|n| *n != u32::MAX && n.to_string() == *key)
    });
    let (numeric, named): (Vec<_>, Vec<_>) = entries.into_iter().partition(|(key, _)| {
        key.parse::<u32>()
            .ok()
            .is_some_and(|n| n != u32::MAX && n.to_string() == *key)
    });
    let entries = numeric
        .into_iter()
        .chain(named)
        .map(|(key, value)| {
            let key = if key.starts_with(|c: char| c.is_ascii_digit()) {
                string(&key)
            } else {
                key
            };
            format!("{key}: {}", string(&value))
        })
        .collect();
    format!("{paths}\n{}", collection('{', '}', entries))
}

#[cfg(test)]
mod tests {
    #[test]
    fn familiar_preview_and_last_temporary_value() {
        let result = super::format(
            &[".env".into()],
            &[
                ("MODE".into(), "old".into()),
                ("MODE".into(), "test".into()),
            ],
        );
        assert_eq!(result, "[ '.env' ]\n{ MODE: 'test' }");
    }
}
