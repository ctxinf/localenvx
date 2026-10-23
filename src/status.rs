//! Non-decrypting startup overview. Never display credential or variable values.
use std::fmt::Write;
use std::path::PathBuf;

use crate::{config, envfile::EnvFile, load};

pub fn format(files: &[PathBuf], cascade: Option<&str>) -> String {
    let mut out = format!("localenvx v{}\nStatus:\n", crate::VERSION);
    if let Ok(dir) = config::config_dir() {
        let path = dir.join("config.toml");
        let _ = writeln!(
            out,
            "  User config: {} ({})",
            path.display(),
            presence(&path)
        );
    }
    match config::config_path() {
        Ok(path) => {
            let state = match path.try_exists() {
                Ok(false) => "not generated; run localenvx manage init",
                Ok(true) => match config::load() {
                    Ok(_) => "initialized",
                    Err(_) => "unusable (invalid configuration or permissions)",
                },
                Err(_) => "unavailable",
            };
            let _ = writeln!(out, "  Active config: {} ({state})", path.display());
        }
        Err(_) => {
            out.push_str("  Active config: unavailable; check HOME or LOCALENVX_CONFIG_DIR\n")
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let _ = writeln!(out, "  Directory: {}", cwd.display());
        for dir in cwd.ancestors() {
            let path = dir.join(".localenvx/config.toml");
            if dir == cwd || path.exists() {
                let _ = writeln!(
                    out,
                    "  Project config: {} ({})",
                    path.display(),
                    presence(&path)
                );
            }
        }
    }
    let mut paths = load::planned_paths(files, cascade);
    if files.is_empty() {
        match std::fs::read_dir(".") {
            Ok(entries) => {
                let mut discovered: Vec<_> = entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        (name == ".env" || name.starts_with(".env.")) && !name.ends_with(".tmp")
                    })
                    .map(|entry| PathBuf::from(entry.file_name()))
                    .collect();
                discovered.sort();
                for path in discovered {
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
            Err(_) => out.push_str("  Environment file discovery: unavailable\n"),
        }
    }
    out.push_str("  Environment files (values hidden; no decryption):\n");
    for path in paths {
        match path.try_exists() {
            Ok(false) => {
                let _ = writeln!(out, "    {}: not found", path.display());
            }
            Ok(true) => match EnvFile::load(&path) {
                Ok(file) => {
                    let mut names = std::collections::HashSet::new();
                    let vars: Vec<_> = file
                        .vars()
                        .filter(|var| names.insert(var.name.as_str()))
                        .map(|var| file.get(&var.name).unwrap())
                        .collect();
                    let encrypted = vars.iter().filter(|var| var.is_encrypted()).count();
                    let _ = writeln!(
                        out,
                        "    {}: {} variables, {} encrypted, {} plaintext [{}]",
                        path.display(),
                        vars.len(),
                        encrypted,
                        vars.len() - encrypted,
                        file.mode.as_str()
                    );
                }
                Err(_) => {
                    let _ = writeln!(out, "    {}: unreadable or invalid", path.display());
                }
            },
            Err(_) => {
                let _ = writeln!(out, "    {}: unavailable", path.display());
            }
        }
    }
    out.push_str("\nSuggestions:\n  localenvx --help                 Show commands and options\n  localenvx manage init                   Create user credentials\n  localenvx manage init --config-file .localenvx/config.toml         Create project credentials\n  localenvx run -- <command>       Run with environment variables\n  localenvx manage ls                   List variable names and encryption status\n");
    out
}

fn presence(path: &std::path::Path) -> &'static str {
    match path.try_exists() {
        Ok(true) => "generated",
        Ok(false) => "not generated",
        Err(_) => "unavailable",
    }
}
