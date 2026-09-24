//! Layered multi-file loading: precedence increases left to right (rightmost wins).

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto;
use crate::envfile::EnvFile;
use crate::session::Session;

pub struct Entry {
    pub name: String,
    pub value: Zeroizing<String>,
    pub encrypted: bool,
    pub source: PathBuf,
}

#[derive(Default)]
pub struct Loaded {
    pub entries: Vec<Entry>,
    /// (variable name, overridden file, winning file)
    pub overrides: Vec<(String, PathBuf, PathBuf)>,
    pub files: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
}

impl Loaded {
    pub fn decrypted_names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.encrypted)
            .map(|e| e.name.as_str())
            .collect()
    }
    pub fn plain_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.encrypted).count()
    }
}

/// `explicit` false means we fell back to the default `.env`: a missing file only warns.
pub fn load_files(sess: &mut Session, paths: &[PathBuf], explicit: bool) -> Result<Loaded> {
    let mut out = Loaded::default();
    for path in paths {
        if !path.exists() {
            if explicit {
                bail!("file not found: {}", path.display());
            }
            out.missing.push(path.clone());
            continue;
        }
        let file = EnvFile::load(path)?;
        out.files.push(path.clone());
        for var in file.vars() {
            let encrypted = var.is_encrypted();
            let value = if encrypted {
                crypto::decrypt(sess.key()?, &var.name, &var.value)?
            } else {
                Zeroizing::new(var.value.clone())
            };
            match out.entries.iter().position(|e| e.name == var.name) {
                Some(i) => {
                    let prev = out.entries[i].source.clone();
                    if prev != *path {
                        out.overrides.push((var.name.clone(), prev, path.clone()));
                    }
                    out.entries[i] = Entry {
                        name: var.name.clone(),
                        value,
                        encrypted,
                        source: path.clone(),
                    };
                }
                None => out.entries.push(Entry {
                    name: var.name.clone(),
                    value,
                    encrypted,
                    source: path.clone(),
                }),
            }
        }
    }
    Ok(out)
}

pub fn default_paths(files: &[PathBuf]) -> (Vec<PathBuf>, bool) {
    if files.is_empty() {
        (vec![PathBuf::from(".env")], false)
    } else {
        (files.to_vec(), true)
    }
}

/// Minimal glob: supports `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some(c) => !t.is_empty() && t[0] == *c && go(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

pub fn path_label(p: &Path) -> String {
    p.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn globs() {
        assert!(glob_match("*_SECRET", "APP_SECRET"));
        assert!(glob_match("*", "ANY"));
        assert!(glob_match("API_?", "API_X"));
        assert!(!glob_match("*_KEY", "KEY_A"));
        assert!(glob_match("EXACT", "EXACT"));
    }
}
