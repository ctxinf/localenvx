//! 格式保持的 .env CST 解析器。
//!
//! 重写文件时保留：注释、空行、变量顺序、引号风格、`export ` 前缀、行内注释。
//! 因此这里不是「parse 成 map 再序列化」，而是把每一行原样留在 CST 里，
//! 只对真正改动的变量行做最小化重写。

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub const MODE_TAG: &str = "@localenvx-mode:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Whitelist,
    Blacklist,
}

impl Mode {
    /// 无 `@localenvx-mode:` 标记时的默认：默认加密，安全的那一侧。
    pub const DEFAULT: Mode = Mode::Blacklist;

    /// 该模式下「无显式标记」的变量是否加密。
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
}

#[derive(Clone, Debug)]
pub struct Var {
    pub name: String,
    /// 已解码的值（去引号、已反转义）。可能是 `encrypted:v1:...`。
    pub value: String,
    pub quote: Quote,
    pub export: bool,
    indent: String,
    space_after_eq: String,
    /// 行内注释等尾随内容，原样保留。
    trailing: String,
}

#[derive(Clone, Debug)]
enum Line {
    Raw(String),
    Var(Var),
}

/// `Line` 的只读视图，把「空行」从「注释」里分出来，方便调用方渲染。
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
}

impl EnvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取 {} 失败", path.display()))?;
        Self::from_str_at(&text, path)
    }

    pub fn empty_at(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            mode: Mode::DEFAULT,
            lines: vec![],
            ends_with_newline: true,
        }
    }

    pub fn from_str_at(text: &str, path: &Path) -> Result<Self> {
        let ends_with_newline = text.is_empty() || text.ends_with('\n');
        let body = text.strip_suffix('\n').unwrap_or(text);
        let mut lines: Vec<Line> = Vec::new();
        if !(text.is_empty()) {
            for raw in body.split('\n') {
                lines.push(match parse_var_line(raw) {
                    Some(v) => Line::Var(v),
                    None => Line::Raw(raw.to_string()),
                });
            }
        }
        let mode = detect_mode(&lines, path)?;
        let f = Self {
            path: path.to_path_buf(),
            mode,
            lines,
            ends_with_newline,
        };
        f.validate_directives()?;
        Ok(f)
    }

    /// 按文件顺序遍历每一行（含注释与空行）——UI 用它把 .env 原样渲染出来。
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
        self.vars().find(|v| v.name == name)
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.lines
            .iter()
            .position(|l| matches!(l, Line::Var(v) if v.name == name))
    }

    /// 变量的有效加密意图：显式指令优先，否则跟随文件模式。
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

    /// 只看紧邻上方、中间无空行的连续注释块。
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
                    "{}:{}: 同一行同时出现 @ENC 与 @PLAIN",
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
                            "{}:{}: 同一变量上方同时出现 @ENC 与 @PLAIN",
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
        let idx = self
            .index_of(name)
            .with_context(|| format!("{}: 没有变量 {name}", self.path.display()))?;
        if let Line::Var(v) = &mut self.lines[idx] {
            v.value = value.to_string();
            if v.quote == Quote::None && needs_quote(value) {
                v.quote = Quote::Double;
            }
        }
        Ok(())
    }

    /// 新增或更新变量；`want_enc` 为 None 表示沿用文件默认（不写指令）。
    pub fn upsert(&mut self, name: &str, value: &str, want_enc: Option<bool>) -> Result<()> {
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

    /// 让 `name` 的有效加密意图等于 `want`：与文件默认一致则去掉多余指令，
    /// 否则写入 / 修正指令注释。
    pub fn apply_directive(&mut self, name: &str, want: bool) -> Result<()> {
        let idx = self
            .index_of(name)
            .with_context(|| format!("{}: 没有变量 {name}", self.path.display()))?;
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

    /// 删除变量行，以及紧邻其上、仅含指令的注释行。
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let idx = self
            .index_of(name)
            .with_context(|| format!("{}: 没有变量 {name}", self.path.display()))?;
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

    /// 原子写回，权限 0600。
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
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
            .with_context(|| format!("写入 {} 失败", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("替换 {} 失败", self.path.display()))?;
        Ok(())
    }
}

impl Var {
    pub fn is_encrypted(&self) -> bool {
        crate::crypto::is_encrypted(&self.value)
    }

    fn render(&self) -> String {
        let quote = match self.quote {
            Quote::None if needs_quote(&self.value) => Quote::Double,
            q => q,
        };
        let value = match quote {
            Quote::None => self.value.clone(),
            Quote::Single => format!("'{}'", self.value),
            Quote::Double => format!("\"{}\"", escape_double(&self.value)),
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
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c => s.push(c),
        }
    }
    s
}

fn unescape_double(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// `# @localenvx-mode:` 只在第一个变量之前生效；之后出现一律忽略。
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
                    other => bail!("{}: 未知的 {MODE_TAG}{other}", path.display()),
                };
                match mode {
                    Some(prev) if prev != found => {
                        bail!(
                            "{}: 同时出现 blacklist 与 whitelist 模式标记",
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

fn parse_var_line(raw: &str) -> Option<Var> {
    let indent_len = raw.len() - raw.trim_start().len();
    let indent = raw[..indent_len].to_string();
    let mut rest = &raw[indent_len..];
    if rest.starts_with('#') || rest.trim().is_empty() {
        return None;
    }
    let export = if let Some(r) = rest.strip_prefix("export ") {
        rest = r.trim_start();
        true
    } else {
        false
    };
    let eq = rest.find('=')?;
    let name = &rest[..eq];
    if name.is_empty() || !name.chars().next()?.is_ascii_alphabetic() && !name.starts_with('_') {
        return None;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let after = &rest[eq + 1..];
    let space_len = after.len() - after.trim_start_matches([' ', '\t']).len();
    let space_after_eq = after[..space_len].to_string();
    let body = &after[space_len..];

    let (quote, value, trailing) = match body.chars().next() {
        Some(q @ ('"' | '\'')) => {
            let bytes = body.as_bytes();
            let mut i = 1;
            let mut end = None;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c == '\\' && q == '"' {
                    i += 2;
                    continue;
                }
                if c == q {
                    end = Some(i);
                    break;
                }
                i += 1;
            }
            let end = end?; // 未闭合的引号：不当作变量行，原样保留
            let inner = &body[1..end];
            let value = if q == '"' {
                unescape_double(inner)
            } else {
                inner.to_string()
            };
            let quote = if q == '"' {
                Quote::Double
            } else {
                Quote::Single
            };
            (quote, value, body[end + 1..].to_string())
        }
        _ => {
            let cut = body
                .char_indices()
                .find(|(i, c)| *c == '#' && (*i == 0 || body[..*i].ends_with([' ', '\t'])))
                .map(|(i, _)| i)
                .unwrap_or(body.len());
            let head = &body[..cut];
            let value = head.trim_end();
            (
                Quote::None,
                value.to_string(),
                body[value.len()..].to_string(),
            )
        }
    };

    Some(Var {
        name: name.to_string(),
        value,
        quote,
        export,
        indent,
        space_after_eq,
        trailing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> EnvFile {
        EnvFile::from_str_at(s, Path::new(".env")).unwrap()
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

        let w = parse("# @localenvx-mode:whitelist\nX=1\n\n# @ENC 生产 key\nY=2\n");
        assert_eq!(w.mode, Mode::Whitelist);
        assert!(!w.should_encrypt("X"));
        assert!(w.should_encrypt("Y"));
    }

    /// 无标记 → blacklist：默认加密，安全的那一侧。
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
        // whitelist 文件里要加密 → 必须写 @ENC
        let mut w = parse("# @localenvx-mode:whitelist\nA=1\n");
        w.upsert("B", "s3cr3t", Some(true)).unwrap();
        assert!(w.render().contains("# @ENC\nB=s3cr3t"));
        w.apply_directive("B", false).unwrap();
        assert!(!w.render().contains("@ENC"));

        // blacklist（默认）文件里要加密 → 跟默认一致，不写多余指令
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
