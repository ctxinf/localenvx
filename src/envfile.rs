//! Format-preserving .env CST parser.
//!
//! Rewriting a file preserves comments, blank lines, variable order, quote style,
//! the `export ` prefix and inline comments. So this is not "parse into a map and
//! serialize back": every line is kept verbatim in the CST, and only the variable
//! lines that actually changed are rewritten, minimally.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub const MODE_TAG: &str = "@localenvx-mode:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Whitelist,
    Blacklist,
}

impl Mode {
    /// Default when no `@localenvx-mode:` tag is present: encrypt by default, the safe side.
    pub const DEFAULT: Mode = Mode::Blacklist;

    /// Whether variables without an explicit directive are encrypted in this mode.
    pub fn encrypts_by_default(self) -> bool {
        self == Mode::Blacklist
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Whitelist => "whitelist",
            Mode::Blacklist => "blacklist",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Directive {
    Enc,
    Plain,
}

impl Directive {
    fn token(self) -> &'static str {
        match self {
            Directive::Enc => "@ENC",
            Directive::Plain => "@PLAIN",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quote {
    None,
    Single,
    Double,
    Backtick,
}

#[derive(Clone, Debug)]
pub struct Var {
    pub name: String,
    /// The decoded value (unquoted, unescaped). May be `encrypted:v1:...`.
    pub value: String,
    pub quote: Quote,
    pub export: bool,
    original: Option<String>,
    indent: String,
    space_after_eq: String,
    /// Trailing content such as an inline comment, kept verbatim.
    trailing: String,
}

#[derive(Clone, Debug)]
enum Line {
    Raw(String),
    Var(Var),
}

/// Read-only view of a `Line`, splitting blank lines out of comments so callers can render them.
pub enum Item<'a> {
    Blank,
    Comment(&'a str),
    Var(&'a Var),
}

pub struct EnvFile {
    pub path: PathBuf,
    pub mode: Mode,
    lines: Vec<Line>,
    ends_with_newline: bool,
    original_source: Option<String>,
}

impl EnvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_str_at(&text, path)
    }

    pub fn empty_at(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            mode: Mode::DEFAULT,
            lines: vec![],
            ends_with_newline: true,
            original_source: None,
        }
    }

    pub fn from_str_at(text: &str, path: &Path) -> Result<Self> {
        let original_source = Some(text.to_string());
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let text = normalized.as_str();
        let ends_with_newline = text.is_empty() || text.ends_with('\n');
        let mut lines = Vec::new();
        let mut cursor = 0;
        for captures in dotenv_pattern().captures_iter(text) {
            let name = captures.get(1).unwrap();
            let value = captures.get(3);
            let start = text[..name.start()]
                .rfind('\n')
                .map_or(0, |i| i + 1)
                .max(cursor);
            let value_end = value.map_or_else(|| captures.get(2).unwrap().end(), |v| v.end());
            let end = text[value_end..]
                .find('\n')
                .map_or(text.len(), |i| value_end + i);
            append_raw(&mut lines, &text[cursor..start]);
            let original = &text[start..end];
            let decoded = value.map_or("", |v| v.as_str()).trim();
            let (quote, value) = match decoded.as_bytes().first().copied() {
                Some(q @ (b'\'' | b'"' | b'`'))
                    if decoded.len() >= 2 && decoded.as_bytes().last() == Some(&q) =>
                {
                    let inner = &decoded[1..decoded.len() - 1];
                    let quote = match q {
                        b'\'' => Quote::Single,
                        b'"' => Quote::Double,
                        _ => Quote::Backtick,
                    };
                    (
                        quote,
                        if q == b'"' {
                            unescape_double(inner)
                        } else {
                            inner.to_string()
                        },
                    )
                }
                _ => (
                    Quote::None,
                    if decoded.starts_with('"') {
                        unescape_double(decoded)
                    } else {
                        decoded.to_string()
                    },
                ),
            };
            let prefix = &text[start..name.start()];
            let indent_len = prefix.len() - prefix.trim_start().len();
            let trailing_start = captures.get(3).map_or(value_end, |v| v.end());
            lines.push(Line::Var(Var {
                name: name.as_str().to_string(),
                value,
                quote,
                export: prefix[indent_len..].starts_with("export"),
                original: Some(original.to_string()),
                indent: prefix[..indent_len].to_string(),
                space_after_eq: String::new(),
                trailing: text[trailing_start..end].to_string(),
            }));
            cursor = end + usize::from(end < text.len());
        }
        append_raw(&mut lines, &text[cursor..]);
        let mode = detect_mode(&lines, path)?;
        let f = Self {
            path: path.to_path_buf(),
            mode,
            lines,
            ends_with_newline,
            original_source,
        };
        f.validate_directives()?;
        Ok(f)
    }

    /// Iterate every line in file order (comments and blanks included) — the UI uses this
    /// to render the .env exactly as written.
    pub fn items(&self) -> impl Iterator<Item = Item<'_>> {
        self.lines.iter().map(|l| match l {
            Line::Raw(raw) if raw.trim().is_empty() => Item::Blank,
            Line::Raw(raw) => Item::Comment(raw),
            Line::Var(v) => Item::Var(v),
        })
    }

    pub fn vars(&self) -> impl Iterator<Item = &Var> {
        self.lines.iter().filter_map(|l| match l {
            Line::Var(v) => Some(v),
            _ => None,
        })
    }

    pub fn get(&self, name: &str) -> Option<&Var> {
        self.vars().filter(|v| v.name == name).last()
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.lines
            .iter()
            .rposition(|l| matches!(l, Line::Var(v) if v.name == name))
    }

    /// A variable's effective encryption intent: an explicit directive wins, otherwise the file mode.
    pub fn should_encrypt(&self, name: &str) -> bool {
        match self.index_of(name).and_then(|i| self.directive_at(i)) {
            Some(Directive::Enc) => true,
            Some(Directive::Plain) => false,
            None => self.mode.encrypts_by_default(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn directive_of(&self, name: &str) -> Option<Directive> {
        self.index_of(name).and_then(|i| self.directive_at(i))
    }

    /// Only looks at the contiguous comment block directly above, with no blank line in between.
    fn directive_at(&self, var_idx: usize) -> Option<Directive> {
        self.scan_directive(var_idx).ok().flatten().map(|(d, _)| d)
    }

    fn scan_directive(&self, var_idx: usize) -> Result<Option<(Directive, usize)>> {
        let mut found: Option<(Directive, usize)> = None;
        let mut i = var_idx;
        while i > 0 {
            i -= 1;
            let Line::Raw(raw) = &self.lines[i] else {
                break;
            };
            let t = raw.trim();
            if !t.starts_with('#') {
                break;
            }
            let enc = t.contains(Directive::Enc.token());
            let plain = t.contains(Directive::Plain.token());
            if enc && plain {
                bail!(
                    "{}:{}: @ENC and @PLAIN on the same line",
                    self.path.display(),
                    i + 1
                );
            }
            let here = if enc {
                Some(Directive::Enc)
            } else if plain {
                Some(Directive::Plain)
            } else {
                None
            };
            if let Some(d) = here {
                if let Some((prev, _)) = found {
                    if prev != d {
                        bail!(
                            "{}:{}: both @ENC and @PLAIN above the same variable",
                            self.path.display(),
                            i + 1
                        );
                    }
                } else {
                    found = Some((d, i));
                }
            }
        }
        Ok(found)
    }

    fn validate_directives(&self) -> Result<()> {
        for i in 0..self.lines.len() {
            if matches!(self.lines[i], Line::Var(_)) {
                self.scan_directive(i)?;
            }
        }
        Ok(())
    }

    pub fn set_value(&mut self, name: &str, value: &str) -> Result<()> {
        self.original_source = None;
        let idx = self
            .index_of(name)
            .with_context(|| format!("{}: no variable named {name}", self.path.display()))?;
        if let Line::Var(v) = &mut self.lines[idx] {
            v.original = None;
            v.value = value.to_string();
            if v.quote == Quote::None && needs_quote(value) {
                v.quote = Quote::Double;
            }
        }
        Ok(())
    }

    /// Insert or update a variable; `want_enc` of None means follow the file default (no directive written).
    pub fn upsert(&mut self, name: &str, value: &str, want_enc: Option<bool>) -> Result<()> {
        self.original_source = None;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            bail!("invalid variable name: {name}");
        }
        while self.vars().filter(|v| v.name == name).count() > 1 {
            let first = self
                .lines
                .iter()
                .position(|l| matches!(l, Line::Var(v) if v.name == name))
                .unwrap();
            self.remove_at(first)?;
        }
        if self.index_of(name).is_none() {
            let quote = if needs_quote(value) {
                Quote::Double
            } else {
                Quote::None
            };
            let var = Var {
                name: name.to_string(),
                value: value.to_string(),
                quote,
                export: false,
                original: None,
                indent: String::new(),
                space_after_eq: String::new(),
                trailing: String::new(),
            };
            if !self.lines.is_empty()
                && !matches!(self.lines.last(), Some(Line::Raw(r)) if r.trim().is_empty())
            {
                self.lines.push(Line::Raw(String::new()));
            }
            self.lines.push(Line::Var(var));
        } else {
            self.set_value(name, value)?;
        }
        if let Some(want) = want_enc {
            self.apply_directive(name, want)?;
        }
        Ok(())
    }

    /// Make `name`'s effective encryption intent equal `want`: drop the redundant directive
    /// when it matches the file default, otherwise write or fix the directive comment.
    pub fn apply_directive(&mut self, name: &str, want: bool) -> Result<()> {
        self.original_source = None;
        let idx = self
            .index_of(name)
            .with_context(|| format!("{}: no variable named {name}", self.path.display()))?;
        let existing = self.scan_directive(idx)?;
        let needed = if want == self.mode.encrypts_by_default() {
            None
        } else if want {
            Some(Directive::Enc)
        } else {
            Some(Directive::Plain)
        };

        match (existing, needed) {
            (Some((have, _)), Some(want_d)) if have == want_d => {}
            (Some((have, i)), Some(want_d)) => {
                let Line::Raw(raw) = &self.lines[i] else {
                    unreachable!()
                };
                self.lines[i] = Line::Raw(raw.replace(have.token(), want_d.token()));
            }
            (Some((have, i)), None) => {
                let Line::Raw(raw) = &self.lines[i] else {
                    unreachable!()
                };
                let stripped = raw.replace(have.token(), "");
                if stripped.trim() == "#" || stripped.trim().is_empty() {
                    self.lines.remove(i);
                } else {
                    self.lines[i] = Line::Raw(stripped.trim_end().to_string());
                }
            }
            (None, Some(want_d)) => {
                self.lines
                    .insert(idx, Line::Raw(format!("# {}", want_d.token())));
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Remove every occurrence, including its directive-only comment.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        if self.index_of(name).is_none() {
            bail!("{}: no variable named {name}", self.path.display());
        }
        while let Some(idx) = self.index_of(name) {
            self.remove_at(idx)?;
        }
        Ok(())
    }

    fn remove_at(&mut self, idx: usize) -> Result<()> {
        self.original_source = None;
        let directive_line = self.scan_directive(idx)?.and_then(|(d, i)| {
            let Line::Raw(raw) = &self.lines[i] else {
                return None;
            };
            (raw.trim() == format!("# {}", d.token()) || raw.trim() == format!("#{}", d.token()))
                .then_some(i)
        });
        self.lines.remove(idx);
        if let Some(i) = directive_line {
            self.lines.remove(i);
        }
        Ok(())
    }

    pub fn render(&self) -> String {
        if let Some(source) = &self.original_source {
            return source.clone();
        }
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            match line {
                Line::Raw(r) => out.push_str(r),
                Line::Var(v) => out.push_str(&v.render()),
            }
        }
        if self.ends_with_newline && !out.is_empty() {
            out.push('\n');
        }
        out
    }

    pub fn validate_render(&self) -> Result<()> {
        let text = self.render();
        let reparsed = Self::from_str_at(&text, &self.path)?;
        if self.vars().map(|v| (&v.name, &v.value)).collect::<Vec<_>>()
            != reparsed
                .vars()
                .map(|v| (&v.name, &v.value))
                .collect::<Vec<_>>()
        {
            bail!(
                "{}: value cannot be represented losslessly in dotenv syntax",
                self.path.display()
            );
        }
        Ok(())
    }

    /// Atomic write-back with mode 0600.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        self.validate_render()?;
        let text = self.render();
        let tmp = self.path.with_extension(format!(
            "{}.localenvx.tmp",
            self.path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("env")
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("failed to replace {}", self.path.display()))?;
        Ok(())
    }
}

impl Var {
    pub fn is_encrypted(&self) -> bool {
        crate::crypto::is_encrypted(&self.value)
    }

    fn render(&self) -> String {
        if let Some(original) = &self.original {
            return original.clone();
        }
        let quote = match self.quote {
            Quote::None if needs_quote(&self.value) => Quote::Double,
            q => q,
        };
        let quote = if match quote {
            Quote::Single => self.value.contains('\''),
            Quote::Double => {
                self.value.contains('"') || self.value.contains("\\n") || self.value.contains("\\r")
            }
            Quote::Backtick => self.value.contains('`'),
            Quote::None => false,
        } {
            if !self.value.contains('\'') {
                Quote::Single
            } else if !self.value.contains('`') {
                Quote::Backtick
            } else {
                Quote::Double
            }
        } else {
            quote
        };
        let value = match quote {
            Quote::None => self.value.clone(),
            Quote::Single => format!("'{}'", self.value),
            Quote::Double => format!("\"{}\"", escape_double(&self.value)),
            Quote::Backtick => format!("`{}`", self.value),
        };
        format!(
            "{}{}{}={}{}{}",
            self.indent,
            if self.export { "export " } else { "" },
            self.name,
            self.space_after_eq,
            value,
            self.trailing
        )
    }
}

fn needs_quote(v: &str) -> bool {
    v.chars()
        .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\' | '$' | '`'))
}

fn escape_double(v: &str) -> String {
    v.replace('\n', "\\n").replace('\r', "\\r")
}

fn unescape_double(v: &str) -> String {
    v.replace("\\n", "\n").replace("\\r", "\r")
}

/// `# @localenvx-mode:` only takes effect before the first variable; later occurrences are ignored.
fn detect_mode(lines: &[Line], path: &Path) -> Result<Mode> {
    let mut mode = None;
    for line in lines {
        match line {
            Line::Var(_) => break,
            Line::Raw(raw) => {
                let Some(pos) = raw.find(MODE_TAG) else {
                    continue;
                };
                let rest = &raw[pos + MODE_TAG.len()..];
                let word: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .collect();
                let found = match word.as_str() {
                    "blacklist" => Mode::Blacklist,
                    "whitelist" => Mode::Whitelist,
                    other => bail!("{}: unknown {MODE_TAG}{other}", path.display()),
                };
                match mode {
                    Some(prev) if prev != found => {
                        bail!(
                            "{}: both blacklist and whitelist mode tags present",
                            path.display()
                        )
                    }
                    _ => mode = Some(found),
                }
            }
        }
    }
    Ok(mode.unwrap_or(Mode::DEFAULT))
}

fn dotenv_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| regex::Regex::new(
        r#"(?m)^[\s\u{feff}]*(?:export[\s\u{feff}]+)?([A-Za-z0-9_.-]+)([\s\u{feff}]*=[\s\u{feff}]*?|:[\s\u{feff}]+?)([\s\u{feff}]*'(?:\\'|[^'])*'|[\s\u{feff}]*"(?:\\"|[^"])*"|[\s\u{feff}]*`(?:\\`|[^`])*`|[^#\r\n]+)?[\s\u{feff}]*(?:#.*)?$"#
    ).expect("valid dotenv 17.1.0 assignment pattern"))
}

fn append_raw(lines: &mut Vec<Line>, raw: &str) {
    if raw.is_empty() {
        return;
    }
    let raw = raw.strip_suffix('\n').unwrap_or(raw);
    lines.extend(raw.split('\n').map(|line| Line::Raw(line.to_string())));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> EnvFile {
        EnvFile::from_str_at(s, Path::new(".env")).unwrap()
    }

    #[test]
    fn edits_preserve_literal_backslashes_and_switch_quotes_when_needed() {
        for value in [
            r"a\nb\r",
            r"C:\new\root",
            "a\"b'c",
            "multi\nline",
            "a\tb\\q",
        ] {
            let mut file = parse("A=old\n");
            file.upsert("A", value, Some(false)).unwrap();
            file.validate_render().unwrap();
            assert_eq!(parse(&file.render()).get("A").unwrap().value, value);
        }
    }

    #[test]
    fn matches_pinned_dotenv_parser_oracle() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/parse-v17.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let file = parse(input);
            assert_eq!(file.render(), input);
            let actual: serde_json::Map<String, serde_json::Value> = file
                .vars()
                .map(|v| (v.name.clone(), v.value.clone().into()))
                .collect();
            assert_eq!(
                serde_json::Value::Object(actual),
                case["expected"],
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn duplicate_keys_use_last_and_edits_remove_stale_entries() {
        let mut f = parse("# @ENC\nA=first\n# keep\n# @PLAIN\nA=last\n");
        assert_eq!(f.get("A").unwrap().value, "last");
        assert!(!f.should_encrypt("A"));
        f.upsert("A", "new", None).unwrap();
        assert_eq!(f.vars().count(), 1);
        assert_eq!(f.get("A").unwrap().value, "new");
        assert!(f.render().contains("# keep"));
        let mut f = parse("A=first\nA=last\nB=stay\n");
        f.remove("A").unwrap();
        assert!(f.get("A").is_none());
        assert!(f.get("B").is_some());
    }

    #[test]
    fn dotenv_syntax_and_lossless_formatting() {
        let src = "export FOO = bar   # inline\n";
        let mut f = parse(src);
        assert_eq!(f.get("FOO").unwrap().value, "bar");
        f.set_value("FOO", "new").unwrap();
        assert_eq!(parse(&f.render()).get("FOO").unwrap().value, "new");
        let src = "1.A-B: hello\nC=abc#comment\nD=`multi\nline`\nE=\"a\\tb\\q\\n\"\n";
        let f = parse(src);
        assert_eq!(f.render(), src);
        assert_eq!(f.get("1.A-B").unwrap().value, "hello");
        assert_eq!(f.get("C").unwrap().value, "abc");
        assert_eq!(f.get("D").unwrap().value, "multi\nline");
        assert_eq!(f.get("E").unwrap().value, "a\\tb\\q\n");
    }

    #[test]
    fn roundtrip_preserves_format() {
        let src = "# hi\n\nexport FOO = bar   # inline\nBAZ='q u x'\nEMPTY=\n";
        assert_eq!(parse(src).render(), src);
    }

    #[test]
    fn parses_values() {
        let f = parse("A=1\nB=\"a\\nb\"\nC='raw\\n'\nD=v # c\n");
        assert_eq!(f.get("A").unwrap().value, "1");
        assert_eq!(f.get("B").unwrap().value, "a\nb");
        assert_eq!(f.get("C").unwrap().value, "raw\\n");
        assert_eq!(f.get("D").unwrap().value, "v");
    }

    #[test]
    fn mode_and_directives() {
        let f = parse("# @localenvx-mode:blacklist\n\n# @PLAIN\nA=1\n\nB=2\n");
        assert_eq!(f.mode, Mode::Blacklist);
        assert!(!f.should_encrypt("A"));
        assert!(f.should_encrypt("B"));

        let w = parse("# @localenvx-mode:whitelist\nX=1\n\n# @ENC production key\nY=2\n");
        assert_eq!(w.mode, Mode::Whitelist);
        assert!(!w.should_encrypt("X"));
        assert!(w.should_encrypt("Y"));
    }

    /// No tag → blacklist: encrypt by default, the safe side.
    #[test]
    fn default_mode_is_blacklist() {
        let f = parse("A=1\n\n# @PLAIN\nB=2\n");
        assert_eq!(f.mode, Mode::Blacklist);
        assert!(f.should_encrypt("A"));
        assert!(!f.should_encrypt("B"));
    }

    #[test]
    fn mode_tag_after_first_var_is_ignored() {
        let f = parse("A=1\n# @localenvx-mode:whitelist\nB=2\n");
        assert_eq!(f.mode, Mode::Blacklist);
    }

    #[test]
    fn conflicting_mode_tags_error() {
        assert!(
            EnvFile::from_str_at(
                "# @localenvx-mode:blacklist\n# @localenvx-mode:whitelist\nA=1\n",
                Path::new(".env")
            )
            .is_err()
        );
    }

    #[test]
    fn conflicting_directives_error() {
        assert!(EnvFile::from_str_at("# @ENC\n# @PLAIN\nA=1\n", Path::new(".env")).is_err());
    }

    #[test]
    fn blank_line_breaks_directive() {
        let f = parse("# @ENC\n\nA=1\n");
        assert_eq!(f.directive_of("A"), None);
    }

    #[test]
    fn upsert_writes_directive() {
        // Encrypting in a whitelist file → @ENC must be written
        let mut w = parse("# @localenvx-mode:whitelist\nA=1\n");
        w.upsert("B", "s3cr3t", Some(true)).unwrap();
        assert!(w.render().contains("# @ENC\nB=s3cr3t"));
        w.apply_directive("B", false).unwrap();
        assert!(!w.render().contains("@ENC"));

        // Encrypting in a blacklist (default) file → matches the default, no directive written
        let mut b = parse("A=1\n");
        b.upsert("B", "s3cr3t", Some(true)).unwrap();
        assert!(!b.render().contains("@ENC"));
        b.apply_directive("B", false).unwrap();
        assert!(b.render().contains("# @PLAIN\nB=s3cr3t"));
    }

    #[test]
    fn remove_drops_directive_line() {
        let mut f = parse("# @ENC\nA=1\nB=2\n");
        f.remove("A").unwrap();
        assert_eq!(f.render(), "B=2\n");
    }

    #[test]
    fn value_update_keeps_quote_style() {
        let mut f = parse("A='x'\nB=y\n");
        f.set_value("A", "z").unwrap();
        f.set_value("B", "a b").unwrap();
        assert_eq!(f.render(), "A='z'\nB=\"a b\"\n");
    }
}
