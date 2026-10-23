//! Non-decrypting startup overview. Never display credential or variable values.
use std::fmt::Write;
use std::io::IsTerminal;
use std::path::PathBuf;

use crate::{config, envfile::EnvFile, load};

pub fn format(files: &[PathBuf], cascade: Option<&str>) -> String {
    let mut out = format!(
        "{}\n{}\n",
        style("1;36", &format!("🔐 localenvx v{}", crate::VERSION)),
        style("1;36", "📊 Status:")
    );
    let active = config::config_path().ok();
    if let Ok(dir) = config::config_dir() {
        let path = dir.join("config.toml");
        let _ = writeln!(
            out,
            "  👤 User config: {}",
            config_status(&path, active.as_deref())
        );
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut found = false;
        for dir in cwd.ancestors() {
            let path = dir.join(".localenvx/config.toml");
            if path.exists() {
                found = true;
                let _ = writeln!(
                    out,
                    "  📦 Project config: {}",
                    config_status(&path, active.as_deref())
                );
            }
        }
        if !found {
            let _ = writeln!(out, "  📦 Project config: not existed");
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
            Err(_) => {
                let _ = writeln!(
                    out,
                    "  {}",
                    style("33", "⚠️ Environment file discovery: unavailable")
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "\n{}",
        style(
            "1;36",
            "📄 Environment files (values hidden; no decryption):"
        )
    );
    for path in paths {
        match path.try_exists() {
            Ok(false) => {
                let _ = writeln!(
                    out,
                    "    {}",
                    style("33", &format!("⚠️ {}: not found", path.display()))
                );
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
                        "    📄 {}: {} [{}]",
                        path.display(),
                        style(
                            if encrypted > 0 { "32" } else { "2" },
                            &format!(
                                "{} variables, {} encrypted, {} plaintext",
                                vars.len(),
                                encrypted,
                                vars.len() - encrypted
                            )
                        ),
                        style("2", file.mode.as_str())
                    );
                }
                Err(_) => {
                    let _ = writeln!(
                        out,
                        "    {}",
                        style(
                            "31",
                            &format!("❌ {}: unreadable or invalid", path.display())
                        )
                    );
                }
            },
            Err(_) => {
                let _ = writeln!(
                    out,
                    "    {}",
                    style("33", &format!("⚠️ {}: unavailable", path.display()))
                );
            }
        }
    }
    let _ = writeln!(out, "\n{}", style("1;36", "💡 Suggestions:"));
    for (command, description) in [
        ("localenvx --help", "Show commands and options"),
        ("localenvx manage init", "Create user credentials"),
        (
            "localenvx manage init --project",
            "Create project credentials",
        ),
        (
            "localenvx run -- <command>",
            "Run with environment variables",
        ),
        (
            "localenvx manage ls",
            "List variable names and encryption status",
        ),
    ] {
        let _ = writeln!(
            out,
            "  → {}\n    {}",
            style("36", command),
            style("2", description)
        );
    }
    out
}

fn config_status(path: &std::path::Path, active: Option<&std::path::Path>) -> String {
    let state = match path.try_exists() {
        Ok(false) => return style("2", "not existed"),
        Ok(true) if active == Some(path) => match config::load() {
            Ok(_) => style("32", "✅Active"),
            Err(_) => style("31", "❌ unusable (invalid configuration or permissions)"),
        },
        Ok(true) => style("32", "✅ generated"),
        Err(_) => style("33", "⚠️ unavailable"),
    };
    format!("{} ({state})", path.display())
}

// Status is written to stdout; redirected output stays free of ANSI escapes.
fn style(code: &str, text: &str) -> String {
    if std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}
