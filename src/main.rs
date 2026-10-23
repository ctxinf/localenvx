mod config;
mod crypto;
mod envfile;
mod expand;
mod load;
mod preview;
mod session;
mod status;
mod term;
mod ui;

#[cfg(not(unix))]
use anyhow::Context;
use anyhow::{Result, bail};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

use crate::envfile::EnvFile;
use crate::session::Session;
use crate::term::{cyan, dim, green, note, yellow};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "localenvx", bin_name = "localenvx", version,
    disable_help_subcommand = true, args_conflicts_with_subcommands = true, about = env!("CARGO_PKG_DESCRIPTION"),
    help_template = "{about}\n\n{before-help}{usage-heading} {usage}\n\nExamples:\n  localenvx -- node app.js\n  localenvx run -e .env.test -- node app.js\n  localenvx manage get -e .env API_TOKEN\n\n{all-args}{after-help}")]
struct Cli {
    /// Print the bundled usage guide
    #[arg(long, exclusive = true)]
    skill: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Args, Default)]
struct Credentials {
    /// Credential config path. Default: nearest .localenvx/config.toml from the current directory upward, then user config (LOCALENVX_CONFIG_DIR > XDG_CONFIG_HOME/localenvx > ~/.config/localenvx on Unix or %APPDATA%/localenvx on Windows). Init defaults to user config.
    #[arg(long)]
    config_file: Option<PathBuf>,
    /// Silence summaries; use --quiet=false for details
    #[arg(long, short, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    quiet: Option<bool>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load .env and run a command (the run keyword is optional)
    Run(RunEntry),
    /// Manage credentials and environment files
    #[command(subcommand)]
    Manage(ManageCmd),
}

#[derive(Args)]
struct RunEntry {
    #[command(flatten)]
    credentials: Credentials,
    #[command(flatten)]
    env: EnvArgs,
    #[command(flatten)]
    args: RunArgs,
}

#[derive(Args, Default)]
struct Files {
    /// Env files (repeatable); defaults to .env
    #[arg(short = 'e')]
    files: Vec<PathBuf>,
}

macro_rules! entry {
    ($name:ident, $args:ty, $env:ty) => {
        #[derive(Args)]
        struct $name {
            #[command(flatten)]
            credentials: Credentials,
            #[command(flatten)]
            env: $env,
            #[command(flatten)]
            args: $args,
        }
    };
}
#[derive(Args)]
struct InitEntry {
    #[command(flatten)]
    credentials: Credentials,
}
entry!(SetEntry, SetArgs, Files);
entry!(GetEntry, GetArgs, ReadArgs);
entry!(BulkEntry, BulkArgs, Files);
entry!(UiEntry, UiArgs, EmptyArgs);

#[derive(Args, Default)]
struct EmptyArgs {}

#[derive(Subcommand)]
#[command(disable_help_subcommand = true)]
enum ManageCmd {
    /// Show credential and environment-file status
    Status,
    /// Generate a random credential key file
    Init(InitEntry),
    /// Write a variable
    Set(SetEntry),
    /// Print a variable's value
    Get(GetEntry),
    /// List key names and encryption status
    Ls(ListArgs),
    /// Encrypt plaintext values
    Enc(BulkEntry),
    /// Decrypt values to plaintext on disk
    Dec(BulkEntry),
    /// Open the local web UI
    Ui(UiEntry),
}

#[derive(Args, Default, Clone)]
struct ReadArgs {
    /// Env files (repeatable); defaults to .env
    #[arg(short = 'e')]
    files: Vec<PathBuf>,
    /// Override the process environment and let later files win
    #[arg(short = 'o', long = "override")]
    r#override: bool,
    /// Cascade candidates: environment.local, local, environment, base
    #[arg(short = 'c', num_args = 0..=1, default_missing_value = "", conflicts_with = "override")]
    cascade: Option<String>,
    /// Temporary NAME=value (repeatable, applied last without expansion)
    #[arg(short = 'v', value_parser = parse_variable)]
    variables: Vec<(String, String)>,
    /// Leave variable references literal
    #[arg(long)]
    no_expand: bool,
}

#[derive(Args, Default)]
struct EnvArgs {
    #[command(flatten)]
    read: ReadArgs,
    /// Print planned paths and temporary values without reading files or running
    #[arg(long)]
    debug: bool,
}

impl std::ops::Deref for EnvArgs {
    type Target = ReadArgs;
    fn deref(&self) -> &ReadArgs {
        &self.read
    }
}
impl From<&Files> for EnvArgs {
    fn from(files: &Files) -> Self {
        Self {
            read: ReadArgs {
                files: files.files.clone(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

fn parse_variable(input: &str) -> std::result::Result<(String, String), String> {
    let (name, value) = input.split_once('=').ok_or("expected NAME=value")?;
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || value.is_empty()
    {
        return Err("expected a word variable name and nonempty value (NAME=value)".into());
    }
    Ok((name.into(), value.into()))
}

#[derive(Args)]
struct RunArgs {
    /// Command and arguments, optionally preceded by --
    #[arg(trailing_var_arg = true)]
    cmd: Vec<OsString>,
}

#[derive(Args)]
struct SetArgs {
    name: String,
    value: Option<String>,
    /// Force plaintext
    #[arg(long, conflicts_with = "enc")]
    plain: bool,
    /// Force encryption
    #[arg(long)]
    enc: bool,
    /// Read the value from stdin (keeps it out of shell history)
    #[arg(long)]
    stdin: bool,
    /// Skip the write confirmation
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Args)]
struct GetArgs {
    name: String,
}

#[derive(Args)]
struct ListArgs {
    #[command(flatten)]
    files: Files,
    /// List all .env and .env.* files in the current directory
    #[arg(long, conflicts_with = "files")]
    all: bool,
}

#[derive(Args)]
struct BulkArgs {
    /// Variable name or glob, repeatable; encrypt defaults to "every variable this file's mode says should be encrypted" (all of them under blacklist)
    #[arg(short = 'k', long = "key")]
    keys: Vec<String>,
}

#[derive(Args)]
struct UiArgs {
    /// Starting port; if taken, try +1 repeatedly (up to +99)
    #[arg(long, default_value_t = 27500)]
    port: u16,
    /// Fail immediately when the port is taken instead of trying the next one
    #[arg(long)]
    strict_port: bool,
}

fn parse_cli() -> Cli {
    let mut argv: Vec<OsString> = std::env::args_os().collect();
    let root = Cli::command().before_help(format!("localenvx v{VERSION}"));
    if argv.len() == 1 {
        println!("localenvx v{VERSION} — use localenvx --help\nExample: localenvx -- node app.js");
        std::process::exit(0);
    }
    if matches!(argv[1].to_str(), Some("--help" | "-h")) {
        // Show runtime options at the root, without making them global.
        RunEntry::augment_args(root).override_usage("localenvx [OPTIONS] [--] <COMMAND> [ARGS]...\n       localenvx run [OPTIONS] [--] <COMMAND> [ARGS]...\n       localenvx manage <COMMAND>").print_help().unwrap();
        println!();
        std::process::exit(0);
    }
    if !matches!(
        argv[1].to_str(),
        Some("run" | "manage" | "--skill" | "--version" | "-V")
    ) {
        argv.insert(1, "run".into());
    }
    let matches = root.get_matches_from(argv);
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() {
    let cli = parse_cli();
    if let Err(e) = dispatch(&cli) {
        eprintln!("{} {e:#}", term::paint("31;1", "error:"));
        std::process::exit(1);
    }
}

fn configure(c: &Credentials, init: bool, quiet_default: bool) -> Result<()> {
    let quiet = c
        .quiet
        .or_else(|| {
            std::env::var("LOCALENVX_QUIET")
                .ok()
                .and_then(|v| match v.as_str() {
                    "1" | "true" => Some(true),
                    "0" | "false" => Some(false),
                    _ => None,
                })
        })
        .unwrap_or(quiet_default);
    term::set_quiet(quiet);
    let selected = if c.config_file.is_none() && init {
        Some(config::config_dir()?.join("config.toml"))
    } else {
        c.config_file.clone()
    };
    config::select_path(selected);
    Ok(())
}

fn dispatch(cli: &Cli) -> Result<()> {
    if cli.skill {
        print!("{}", include_str!("../SKILL.md"));
        return Ok(());
    }
    match cli.cmd.as_ref() {
        None => Ok(()),
        Some(Cmd::Run(a)) => {
            if a.env.debug {
                println!(
                    "{}",
                    preview::format(
                        &load::planned_paths(&a.env.files, a.env.cascade.as_deref()),
                        &a.env.variables
                    )
                );
                return Ok(());
            }
            configure(&a.credentials, false, true)?;
            cmd_run(&a.args, &a.env)
        }
        Some(Cmd::Manage(cmd)) => match cmd {
            ManageCmd::Init(a) => {
                configure(&a.credentials, true, false)?;
                cmd_init()
            }
            ManageCmd::Status => {
                config::select_path(None);
                print!("{}", status::format(&[], None));
                Ok(())
            }
            ManageCmd::Set(a) => {
                configure(&a.credentials, false, false)?;
                cmd_set(&a.args, &(&a.env).into())
            }
            ManageCmd::Get(a) => {
                configure(&a.credentials, false, false)?;
                cmd_get(
                    &a.args,
                    &EnvArgs {
                        read: a.env.clone(),
                        debug: false,
                    },
                )
            }
            ManageCmd::Ls(a) => cmd_list(a),
            ManageCmd::Enc(a) => {
                configure(&a.credentials, false, false)?;
                cmd_encrypt(&a.args, &(&a.env).into())
            }
            ManageCmd::Dec(a) => {
                configure(&a.credentials, false, false)?;
                cmd_decrypt(&a.args, &(&a.env).into())
            }
            ManageCmd::Ui(a) => {
                configure(&a.credentials, false, false)?;
                ui::serve(a.args.port, a.args.strict_port)
            }
        },
    }
}

// ── F6 init ──────────────────────────────────────────────────────────────────

/// Ciphertexts have no credential identifier, so reject any existing encryption.
/// Do not follow directory symlinks (which could leave the project or form cycles).
fn check_project_initialization(root: &std::path::Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                if name != ".git" {
                    pending.push(entry.path());
                }
            } else if name == ".env" || name.starts_with(".env.") {
                // File symlinks are checked too: runtime loading follows them.
                let file = EnvFile::load(&entry.path()).map_err(|_| {
                    anyhow::anyhow!(
                        "cannot initialize project credentials: cannot inspect {}",
                        entry.path().display()
                    )
                })?;
                if file.vars().any(|var| var.is_encrypted()) {
                    bail!(
                        "cannot initialize project credentials: {} contains encrypted values that may use user credentials; decrypt existing values with the original credentials first (no files changed)",
                        entry.path().display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn cmd_init() -> Result<()> {
    let path = config::config_path()?;
    if path.exists() {
        bail!(
            "{} already exists; existing credentials are never overwritten",
            path.display()
        );
    }
    // Explicit project paths retain the same initialization checks.
    if let Some(dir) = path
        .parent()
        .filter(|dir| dir.file_name().is_some_and(|name| name == ".localenvx"))
    {
        let root = dir
            .parent()
            .filter(|root| !root.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        check_project_initialization(root)?;
    }
    let cfg = config::Config::new()?;
    let written = config::save(&cfg)?;
    note!(
        "{} {}",
        green("✓ initialized"),
        dim(&written.display().to_string())
    );
    note!("  Back up this credential file; it is the key to your encrypted values.");
    Ok(())
}

// ── F2/F3/F4 run ─────────────────────────────────────────────────────────────

type RuntimeEntries = Vec<(String, zeroize::Zeroizing<String>)>;

fn runtime_environment(env: &EnvArgs) -> Result<(RuntimeEntries, load::Loaded)> {
    let paths = load::planned_paths(&env.files, env.cascade.as_deref());
    let mut sess = Session::open()?;
    let mut loaded = load::load_files(&paths, env.cascade.is_some(), env.r#override)?;
    let entries = load::resolve_environment(&mut sess, &mut loaded, &env.variables, env.no_expand)?;
    if env.cascade.is_some() && loaded.files.is_empty() {
        note!(
            "{} no cascade candidates found; continuing with the process environment",
            yellow("warn:")
        );
    }
    for m in &loaded.missing {
        note!("{} {} not found, skipped", yellow("⚠️"), m.display());
    }
    Ok((entries, loaded))
}

fn cmd_run(a: &RunArgs, env: &EnvArgs) -> Result<()> {
    if a.cmd.is_empty() {
        bail!("missing command after run");
    }
    let (entries, loaded) = runtime_environment(env)?;
    print_summary(&loaded);
    let mut cmd = std::process::Command::new(&a.cmd[0]);
    cmd.args(&a.cmd[1..]);
    cmd.envs(entries.iter().map(|(key, value)| (key, value.as_str())));
    exec(cmd, &a.cmd[0].to_string_lossy())
}

/// Replace ourselves via execve: no shell, so exit codes and signals pass through naturally.
fn exec(mut cmd: std::process::Command, program: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::Error::new(err).context(format!("failed to execute {program}")))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to execute {program}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn print_summary(loaded: &load::Loaded) {
    if term::quiet() || loaded.files.is_empty() {
        return;
    }
    let chain = loaded
        .files
        .iter()
        .map(|p| load::path_label(p))
        .collect::<Vec<_>>()
        .join(" ← ");
    eprintln!("{} {}", dim(&format!("localenvx v{VERSION}")), cyan(&chain));
    let dec = loaded.decrypted_names();
    eprintln!(
        "  {} {} vars loaded  ({} plain, {} decrypted)",
        green("✓"),
        loaded.entries.len(),
        loaded.plain_count(),
        dec.len()
    );
    if !dec.is_empty() {
        eprintln!("  🔓 {}", dec.join("  "));
    }
    for (name, from, to) in &loaded.overrides {
        eprintln!(
            "  {}  {} overrides {} from {}",
            yellow("⚠️"),
            to.display(),
            from.display(),
            name
        );
    }
}

// ── F5 CRUD ─────────────────────────────────────────────────────────────────

fn target_file(env: &EnvArgs) -> Result<&std::path::Path> {
    match env.files.as_slice() {
        [] => Ok(std::path::Path::new(".env")),
        [file] => Ok(file),
        _ => bail!("this command accepts a single -e file"),
    }
}

fn open_or_new(path: &std::path::Path) -> Result<EnvFile> {
    if path.exists() {
        EnvFile::load(path)
    } else {
        Ok(EnvFile::empty_at(path))
    }
}

fn cmd_set(a: &SetArgs, env: &EnvArgs) -> Result<()> {
    let value = match (&a.value, a.stdin) {
        (Some(v), false) => v.clone(),
        (None, true) => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s.trim_end_matches(['\n', '\r']).to_string()
        }
        (Some(_), true) => {
            bail!("--stdin and the positional VALUE argument are mutually exclusive")
        }
        (None, false) => bail!("missing VALUE (or use --stdin to read it from standard input)"),
    };

    let paths = edit_paths(env)?;
    let mut files: Vec<_> = paths
        .iter()
        .map(|path| open_or_new(path))
        .collect::<Result<_>>()?;
    for file in &files {
        eprintln!("write {} to {}", a.name, file.path.display());
        let count = file.vars().filter(|v| v.name == a.name).count();
        if count > 0 {
            eprintln!(
                "{} {}: {} ({} existing occurrence(s) will be replaced)",
                yellow("warn:"),
                file.path.display(),
                a.name,
                count
            );
        }
    }
    if a.stdin && !a.yes {
        bail!("stdin is reserved for input; pass -y to confirm the write");
    }
    if !term::confirm("Write these files?", a.yes)? {
        return Ok(());
    }
    let want_enc = if a.enc {
        Some(true)
    } else if a.plain {
        Some(false)
    } else {
        None
    };
    let mut sess = None;
    for file in &mut files {
        file.upsert(&a.name, "", want_enc)?;
        let encrypt = want_enc.unwrap_or_else(|| file.should_encrypt(&a.name));
        let stored = if encrypt {
            if sess.is_none() {
                sess = Some(Session::open()?);
            }
            crypto::encrypt(sess.as_mut().unwrap().key(), &a.name, &value)?
        } else {
            value.clone()
        };
        file.set_value(&a.name, &stored)?;
        file.validate_render()?;
    }
    for file in &files {
        file.save()?;
        note!("{} {} → {}", green("✓"), a.name, file.path.display());
    }
    Ok(())
}

fn edit_paths(env: &EnvArgs) -> Result<Vec<PathBuf>> {
    let (paths, _) = load::default_paths(&env.files);
    let mut unique = Vec::new();
    let mut identities = std::collections::HashSet::new();
    for path in paths {
        let identity = if path.exists() {
            std::fs::canonicalize(&path)?
        } else {
            std::path::absolute(&path)?
        };
        if identities.insert(identity) {
            unique.push(path);
        }
    }
    Ok(unique)
}

fn cmd_get(a: &GetArgs, env: &EnvArgs) -> Result<()> {
    let (entries, loaded) = runtime_environment(env)?;
    let source = if env.variables.iter().any(|(name, _)| *name == a.name) {
        None
    } else {
        loaded
            .entries
            .iter()
            .find(|entry| entry.name == a.name)
            .map(|entry| &entry.source)
    };
    let mut files: Vec<_> = loaded.files.iter().collect();
    if !env.r#override {
        files.reverse();
    }
    for file in files {
        let status = if source == Some(file) {
            green("effective")
        } else {
            dim("ineffective")
        };
        note!("{}  {}", load::path_label(file), status);
    }
    if let Some((_, value)) = entries.iter().find(|(key, _)| *key == a.name) {
        println!("{}", value.as_str());
    } else if let Some(value) = std::env::var_os(&a.name) {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(value.as_encoded_bytes())?;
        stdout.write_all(b"\n")?;
    } else {
        bail!("no variable named {} in the final environment", a.name);
    }
    Ok(())
}

fn cmd_list(a: &ListArgs) -> Result<()> {
    let paths = if a.all {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(".")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            if (name_text == ".env" || name_text.starts_with(".env."))
                && !name_text.ends_with(".tmp")
                && entry.path().is_file()
            {
                paths.push(PathBuf::from(name));
            }
        }
        paths.sort();
        if paths.is_empty() {
            println!("No .env files found in the current directory.");
        }
        paths
    } else {
        load::default_paths(&a.files.files).0
    };
    for path in &paths {
        let file = EnvFile::load(path)?;
        println!(
            "{}  {}",
            cyan(&path.display().to_string()),
            dim(&format!("[{}]", file.mode.as_str()))
        );
        for v in file.vars() {
            let tag = if v.is_encrypted() {
                green("🔒 enc  ")
            } else {
                dim("   plain")
            };
            println!("  {tag}  {}", v.name);
        }
    }
    Ok(())
}

/// Pick, in file order, the variable names matching any of the globs.
fn selected(file: &EnvFile, keys: &[String]) -> Vec<String> {
    file.vars()
        .filter(|v| keys.iter().any(|k| load::glob_match(k, &v.name)))
        .map(|v| v.name.clone())
        .collect()
}

fn cmd_encrypt(a: &BulkArgs, env: &EnvArgs) -> Result<()> {
    let mut file = EnvFile::load(target_file(env)?)?;
    let names: Vec<String> = if a.keys.is_empty() {
        file.vars()
            .filter(|v| !v.is_encrypted() && file.should_encrypt(&v.name))
            .map(|v| v.name.clone())
            .collect()
    } else {
        selected(&file, &a.keys)
            .into_iter()
            .filter(|n| !file.get(n).unwrap().is_encrypted())
            .collect()
    };
    if names.is_empty() {
        // Explain an empty result, otherwise it looks like a bug.
        note!(
            "{} {} is in {} mode; nothing needs encrypting",
            dim("·"),
            target_file(env)?.display(),
            file.mode.as_str()
        );
        if a.keys.is_empty() && file.mode == envfile::Mode::Whitelist {
            note!(
                "  under whitelist only variables marked {} are encrypted; pass {} or put {} before the first variable to encrypt by default",
                dim("# @ENC"),
                dim("-k '*_TOKEN'"),
                dim("# @localenvx-mode:blacklist")
            );
        }
        return Ok(());
    }
    let sess = Session::open()?;
    for name in &names {
        let plain = file.get(name).unwrap().value.clone();
        let ct = crypto::encrypt(sess.key(), name, &plain)?;
        file.set_value(name, &ct)?;
        if !a.keys.is_empty() {
            file.apply_directive(name, true)?;
        }
    }
    file.save()?;
    note!(
        "{} encrypted {} item(s): {}",
        green("✓"),
        names.len(),
        names.join(" ")
    );
    Ok(())
}

fn cmd_decrypt(a: &BulkArgs, env: &EnvArgs) -> Result<()> {
    if a.keys.is_empty() {
        bail!(
            "decrypt requires an explicit -k (plaintext lands on disk, so there is no bulk default)"
        );
    }
    let mut file = EnvFile::load(target_file(env)?)?;
    let names: Vec<String> = selected(&file, &a.keys)
        .into_iter()
        .filter(|n| file.get(n).unwrap().is_encrypted())
        .collect();
    if names.is_empty() {
        note!("{} no encrypted variable matched", dim("·"));
        return Ok(());
    }
    let sess = Session::open()?;
    for name in &names {
        let ct = file.get(name).unwrap().value.clone();
        let pt = crypto::decrypt(sess.key(), name, &ct)?;
        file.set_value(name, &pt)?;
        file.apply_directive(name, false)?;
    }
    file.save()?;
    note!(
        "{} decrypted {} item(s) to plaintext: {}",
        yellow("⚠️"),
        names.len(),
        names.join(" ")
    );
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn runtime_options_stop_at_child_command() {
        for separator in [false, true] {
            let mut argv = vec!["localenvx", "run", "-e", "first.vars"];
            if separator {
                argv.push("--");
            }
            argv.extend(["echo", "-e", "child", "--help"]);
            let cli = Cli::try_parse_from(argv).unwrap();
            let Some(Cmd::Run(entry)) = cli.cmd else {
                panic!("expected run")
            };
            assert_eq!(entry.env.files, vec![PathBuf::from("first.vars")]);
            assert_eq!(entry.args.cmd, vec!["echo", "-e", "child", "--help"]);
        }
    }

    #[test]
    fn management_options_are_local_to_each_command() {
        let cli = Cli::try_parse_from(["localenvx", "manage", "get", "-q=false", "KEY"]).unwrap();
        let Some(Cmd::Manage(ManageCmd::Get(entry))) = cli.cmd else {
            panic!("expected get")
        };
        assert_eq!(entry.credentials.quiet, Some(false));
        for argv in [
            vec!["localenvx", "manage", "-e", "file", "get", "KEY"],
            vec!["localenvx", "manage", "init", "-v", "KEY=value"],
            vec!["localenvx", "manage", "init", "--project"],
            vec!["localenvx", "manage", "ls", "--no-expand"],
            vec!["localenvx", "--skill", "manage", "status"],
        ] {
            assert!(Cli::try_parse_from(argv).is_err());
        }
    }
}
