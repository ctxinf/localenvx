//! Select final sources before decrypting; dotenv-cli file precedence.

use anyhow::{Context, Result};
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

/// Missing paths are tolerated only for cascade candidates.
pub fn load_files(
    sess: &mut Session,
    paths: &[PathBuf],
    allow_missing: bool,
    override_env: bool,
    variables: &[(String, String)],
) -> Result<Loaded> {
    let mut out = Loaded::default();
    let mut files = Vec::new();
    for path in paths {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                files.push(EnvFile::from_str_at(&text, path)?);
                out.files.push(path.clone());
            }
            Err(e) if allow_missing && e.kind() == std::io::ErrorKind::NotFound => {
                out.missing.push(path.clone())
            }
            Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }
    select_files(&mut out, &files, override_env);
    // Do not derive a key or validate ciphertext that cannot reach the child.
    out.entries.retain(|entry| {
        !variables.iter().any(|(name, _)| *name == entry.name)
            && (override_env || std::env::var_os(&entry.name).is_none())
    });
    for entry in &mut out.entries {
        if entry.encrypted {
            entry.value = crypto::decrypt(sess.key()?, &entry.name, &entry.value)?;
        }
    }
    Ok(out)
}

fn select_files(out: &mut Loaded, files: &[EnvFile], override_env: bool) {
    for file in files {
        // Within a file the last duplicate wins, independently of cross-file precedence.
        for var in file.vars() {
            let var = file.get(&var.name).unwrap();
            let entry = Entry {
                name: var.name.clone(),
                value: Zeroizing::new(var.value.clone()),
                encrypted: var.is_encrypted(),
                source: file.path.clone(),
            };
            if let Some(i) = out.entries.iter().position(|e| e.name == entry.name) {
                if out.entries[i].source == file.path {
                    continue;
                }
                if override_env {
                    out.overrides.push((
                        entry.name.clone(),
                        out.entries[i].source.clone(),
                        file.path.clone(),
                    ));
                    out.entries[i] = entry;
                } else {
                    out.overrides.push((
                        entry.name.clone(),
                        file.path.clone(),
                        out.entries[i].source.clone(),
                    ));
                }
            } else {
                out.entries.push(entry);
            }
        }
    }
}

pub fn planned_paths(files: &[PathBuf], cascade: Option<&str>) -> Vec<PathBuf> {
    let (bases, _) = default_paths(files);
    bases
        .into_iter()
        .flat_map(|base| {
            let suffix = |suffix: &str| {
                let mut path = base.as_os_str().to_os_string();
                path.push(suffix);
                PathBuf::from(path)
            };
            match cascade {
                Some("") => vec![suffix(".local"), base],
                Some(environment) => vec![
                    suffix(&format!(".{environment}.local")),
                    suffix(".local"),
                    suffix(&format!(".{environment}")),
                    base,
                ],
                None => vec![base],
            }
        })
        .collect()
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
    fn cascade_paths_follow_dotenv_order() {
        use super::*;
        let paths = planned_paths(&[PathBuf::from("config.vars")], Some("test"));
        assert_eq!(
            paths,
            [
                "config.vars.test.local",
                "config.vars.local",
                "config.vars.test",
                "config.vars"
            ]
            .map(PathBuf::from)
        );
        assert_eq!(
            planned_paths(&[], Some("")),
            [".env.local", ".env"].map(PathBuf::from)
        );
    }

    #[test]
    fn file_precedence_and_duplicate_resolution() {
        use super::*;
        let files = vec![
            EnvFile::from_str_at("K=old\nK=first\n", Path::new("first.vars")).unwrap(),
            EnvFile::from_str_at("K=second\n", Path::new("second.vars")).unwrap(),
        ];
        let mut loaded = Loaded::default();
        select_files(&mut loaded, &files, false);
        assert_eq!(&*loaded.entries[0].value, "first");
        let mut loaded = Loaded::default();
        select_files(&mut loaded, &files, true);
        assert_eq!(&*loaded.entries[0].value, "second");
    }

    #[test]
    fn globs() {
        assert!(glob_match("*_SECRET", "APP_SECRET"));
        assert!(glob_match("*", "ANY"));
        assert!(glob_match("API_?", "API_X"));
        assert!(!glob_match("*_KEY", "KEY_A"));
        assert!(glob_match("EXACT", "EXACT"));
    }
}
