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
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

use crate::envfile::EnvFile;
use crate::session::Session;
use crate::term::{cyan, dim, green, note, yellow};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "localenvx",
    bin_name = "localenvx",
    version,
    disable_help_subcommand = true,
    about = "Encrypted environment-variable manager for local development",
    long_about = "No plaintext secrets on disk: sensitive values in .env are stored as XChaCha20-Poly1305\nciphertext, decrypted only during `localenvx run` and passed to the child process via environ."
)]
struct Cli {
    /// Read the password from stdin (highest precedence)
    #[arg(long, global = true)]
    password_stdin: bool,
    /// Credential config path (overrides user and project credentials)
    #[arg(long, global = true, conflicts_with = "project")]
    config_file: Option<PathBuf>,
    /// Use credentials in the current directory's .localenvx/config.toml
    #[arg(long, global = true)]
    project: bool,
    /// Silence summaries (run/get default to true); use --quiet=false for details
    #[arg(long, short, global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    quiet: Option<bool>,
    #[command(flatten)]
    env: EnvArgs,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show commands and options (equivalent to --help)
    Help,
    /// Print the bundled usage guide for people and agents
    Skill,
    /// Show credential and environment-file status without revealing values
    Status,
    #[command(external_subcommand)]
    External(Vec<OsString>),
    /// Generate a salt, set the password and write the config
    Init(InitArgs),
    /// Load .env and exec the child process (no shell involved)
    Run(RunArgs),
    /// Write a variable (the file mode decides whether it is encrypted)
    Set(SetArgs),
    /// Print a single variable's value to stdout
    Get(GetArgs),
    /// List key names and encryption status (never values)
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Remove a variable
    Rm(RmArgs),
    /// Bulk-encrypt existing plaintext values
    #[command(visible_alias = "enc")]
    Encrypt(BulkArgs),
    /// Decrypt to plaintext (careful: plaintext lands on disk)
    #[command(visible_alias = "dec")]
    Decrypt(BulkArgs),
    /// Change the password and re-encrypt the given files with it
    Passwd(PasswdArgs),
    /// Local web UI (127.0.0.1, foreground process, Ctrl-C to quit)
    Ui(UiArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Do not store the password in the config (use LOCALENVX_PASSWORD or type it each time)
    #[arg(long)]
    no_store: bool,
    /// Overwrite an existing config (old ciphertext becomes undecryptable)
    #[arg(long)]
    force: bool,
}

#[derive(Args, Default)]
struct EnvArgs {
    /// Env files (repeatable); defaults to .env
    #[arg(short = 'e', global = true)]
    files: Vec<PathBuf>,
    /// Override the process environment and let later files win
    #[arg(short = 'o', long = "override", global = true)]
    r#override: bool,
    /// Cascade candidates: environment.local, local, environment, base
    #[arg(short = 'c', global = true, num_args = 0..=1, default_missing_value = "", conflicts_with = "override")]
    cascade: Option<String>,
    /// Temporary NAME=value (repeatable, applied last without expansion)
    #[arg(short = 'v', global = true, value_parser = parse_variable)]
    variables: Vec<(String, String)>,
    /// Print planned paths and temporary values without reading files or running
    #[arg(long, global = true)]
    debug: bool,
    /// Leave variable references literal
    #[arg(long, global = true)]
    no_expand: bool,
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
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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
struct ListArgs {}

#[derive(Args)]
struct RmArgs {
    name: String,
    /// Skip the removal confirmation
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Args)]
struct BulkArgs {
    /// Variable name or glob, repeatable; encrypt defaults to "every variable this file's mode says should be encrypted" (all of them under blacklist)
    #[arg(short = 'k', long = "key")]
    keys: Vec<String>,
}

#[derive(Args)]
struct PasswdArgs {
    /// Do not store the new password in the config
    #[arg(long)]
    no_store: bool,
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

fn main() {
    let cli = Cli::parse();
    let quiet_default = matches!(
        cli.cmd,
        Some(Cmd::Run(_) | Cmd::External(_) | Cmd::Get(_)) | None
    );
    let quiet = cli
        .quiet
        .or_else(|| {
            std::env::var("LOCALENVX_QUIET")
                .ok()
                .and_then(|value| match value.as_str() {
                    "1" | "true" => Some(true),
                    "0" | "false" => Some(false),
                    _ => None,
                })
        })
        .unwrap_or(quiet_default);
    term::set_quiet(quiet);
    if let Err(e) = dispatch(&cli) {
        eprintln!("{} {e:#}", term::paint("31;1", "error:"));
        std::process::exit(1);
    }
}

fn dispatch(cli: &Cli) -> Result<()> {
    if matches!(cli.cmd, Some(Cmd::Help)) {
        // Use the same parser path so formatting and global options match --help.
        Cli::command()
            .try_get_matches_from(["localenvx", "--help"])
            .expect_err("--help returns DisplayHelp")
            .print()?;
        return Ok(());
    }
    if matches!(cli.cmd, Some(Cmd::Skill)) {
        print!("{}", include_str!("../SKILL.md"));
        return Ok(());
    }
    if cli.env.debug {
        println!(
            "{}",
            preview::format(
                &load::planned_paths(&cli.env.files, cli.env.cascade.as_deref()),
                &cli.env.variables
            )
        );
        return Ok(());
    }
    let selected = if cli.project {
        Some(std::env::current_dir()?.join(".localenvx/config.toml"))
    } else if cli.config_file.is_none() && matches!(cli.cmd, Some(Cmd::Init(_))) {
        // Initialization remains user-scoped unless a destination is explicit.
        Some(config::config_dir()?.join("config.toml"))
    } else {
        cli.config_file.clone()
    };
    config::select_path(selected);
    match cli.cmd.as_ref() {
        Some(Cmd::External(cmd)) => {
            cmd_run(&RunArgs { cmd: cmd.clone() }, &cli.env, cli.password_stdin)
        }
        None => bail!("missing command; use localenvx --help or localenvx status"),
        Some(Cmd::Help | Cmd::Skill) => unreachable!("help is handled before configuration"),
        Some(Cmd::Status) => {
            print!(
                "{}",
                status::format(&cli.env.files, cli.env.cascade.as_deref())
            );
            Ok(())
        }
        Some(Cmd::Init(a)) => cmd_init(a, cli.project),
        Some(Cmd::Run(a)) => cmd_run(a, &cli.env, cli.password_stdin),
        Some(Cmd::Set(a)) => cmd_set(a, &cli.env, cli.password_stdin),
        Some(Cmd::Get(a)) => cmd_get(a, &cli.env, cli.password_stdin),
        Some(Cmd::List(a)) => cmd_list(a, &cli.env),
        Some(Cmd::Rm(a)) => cmd_rm(a, &cli.env),
        Some(Cmd::Encrypt(a)) => cmd_encrypt(a, &cli.env, cli.password_stdin),
        Some(Cmd::Decrypt(a)) => cmd_decrypt(a, &cli.env, cli.password_stdin),
        Some(Cmd::Passwd(a)) => cmd_passwd(a, &cli.env),
        Some(Cmd::Ui(a)) => ui::serve(a.port, a.strict_port, cli.password_stdin),
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

fn cmd_init(a: &InitArgs, project: bool) -> Result<()> {
    let path = config::config_path()?;
    if path.exists() && !a.force {
        bail!(
            "{} already exists; pass --force to overwrite (old ciphertext becomes undecryptable)",
            path.display()
        );
    }
    if project {
        check_project_initialization(&std::env::current_dir()?)?;
    }
    let pw = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        session::prompt_new_password()?
    } else {
        session::read_password_stdin()?
    };
    let salt = crypto::new_salt_b64()?;
    let stored = (!a.no_store).then(|| pw.to_string());
    let cfg = config::Config::new(salt, crypto::KdfParams::default(), stored);
    let written = config::save(&cfg)?;
    note!(
        "{} {}",
        green("✓ initialized"),
        dim(&written.display().to_string())
    );
    if a.no_store {
        note!("  password not stored: use LOCALENVX_PASSWORD or type it interactively");
    } else {
        note!(
            "  {}",
            yellow(
                "the password is stored in plaintext in the config (0600) — keep a copy in 1Password; if you forget it nothing can be recovered"
            )
        );
    }
    Ok(())
}

// ── F2/F3/F4 run ─────────────────────────────────────────────────────────────

fn runtime_environment(
    env: &EnvArgs,
    password_stdin: bool,
) -> Result<Vec<(String, zeroize::Zeroizing<String>)>> {
    let paths = load::planned_paths(&env.files, env.cascade.as_deref());
    let mut sess = Session::open(password_stdin)?;
    let mut loaded = load::load_files(&paths, env.cascade.is_some(), env.r#override)?;
    let entries = load::resolve_environment(&mut sess, &mut loaded, &env.variables, env.no_expand)?;
    if env.cascade.is_some() && loaded.files.is_empty() {
        eprintln!(
            "{} no cascade candidates found; continuing with the process environment",
            yellow("warn:")
        );
    }
    for m in &loaded.missing {
        note!("{} {} not found, skipped", yellow("⚠️"), m.display());
    }
    print_summary(&loaded);
    Ok(entries)
}

fn cmd_run(a: &RunArgs, env: &EnvArgs, password_stdin: bool) -> Result<()> {
    if a.cmd.is_empty() {
        bail!("missing command after run");
    }
    let entries = runtime_environment(env, password_stdin)?;
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

fn cmd_set(a: &SetArgs, env: &EnvArgs, password_stdin: bool) -> Result<()> {
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
    if (a.stdin || password_stdin) && !a.yes {
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
                sess = Some(Session::open(password_stdin)?);
            }
            crypto::encrypt(sess.as_mut().unwrap().key()?, &a.name, &value)?
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

fn cmd_get(a: &GetArgs, env: &EnvArgs, password_stdin: bool) -> Result<()> {
    let entries = runtime_environment(env, password_stdin)?;
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

fn cmd_list(_a: &ListArgs, env: &EnvArgs) -> Result<()> {
    let (paths, _) = load::default_paths(&env.files);
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

fn cmd_rm(a: &RmArgs, env: &EnvArgs) -> Result<()> {
    let paths = edit_paths(env)?;
    let mut files: Vec<_> = paths
        .iter()
        .map(|path| EnvFile::load(path))
        .collect::<Result<_>>()?;
    files.retain(|file| file.get(&a.name).is_some());
    if files.is_empty() {
        bail!("no variable named {} in the selected files", a.name);
    }
    for file in &mut files {
        let count = file.vars().filter(|v| v.name == a.name).count();
        if count == 0 {
            continue;
        }
        eprintln!(
            "remove {} from {} ({} occurrence(s))",
            a.name,
            file.path.display(),
            count
        );
        file.remove(&a.name)?;
        file.validate_render()?;
    }
    if !term::confirm("Remove from these files?", a.yes)? {
        return Ok(());
    }
    for file in &files {
        file.save()?;
    }
    note!("{} removed {}", green("✓"), a.name);
    Ok(())
}

/// Pick, in file order, the variable names matching any of the globs.
fn selected(file: &EnvFile, keys: &[String]) -> Vec<String> {
    file.vars()
        .filter(|v| keys.iter().any(|k| load::glob_match(k, &v.name)))
        .map(|v| v.name.clone())
        .collect()
}

fn cmd_encrypt(a: &BulkArgs, env: &EnvArgs, password_stdin: bool) -> Result<()> {
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
    let mut sess = Session::open(password_stdin)?;
    for name in &names {
        let plain = file.get(name).unwrap().value.clone();
        let ct = crypto::encrypt(sess.key()?, name, &plain)?;
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

fn cmd_decrypt(a: &BulkArgs, env: &EnvArgs, password_stdin: bool) -> Result<()> {
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
    let mut sess = Session::open(password_stdin)?;
    for name in &names {
        let ct = file.get(name).unwrap().value.clone();
        let pt = crypto::decrypt(sess.key()?, name, &ct)?;
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

// ── F6 passwd ────────────────────────────────────────────────────────────────

fn cmd_passwd(a: &PasswdArgs, env: &EnvArgs) -> Result<()> {
    let cfg = config::load()?;
    let old_pw = match cfg.password.as_deref() {
        Some(p) if !p.is_empty() => zeroize::Zeroizing::new(p.to_string()),
        _ => session::prompt_password("current password: ")?,
    };
    let old_key = crypto::derive_key(&old_pw, &cfg.kdf.salt, cfg.params())?;

    // Decrypt everything first and only change the password if all of it succeeded —
    // a failure halfway through would leave a mixed state.
    type Plaintexts = Vec<(String, zeroize::Zeroizing<String>)>;
    let mut files: Vec<(EnvFile, Plaintexts)> = Vec::new();
    for path in &env.files {
        let file = EnvFile::load(path)?;
        let mut items = Vec::new();
        for v in file.vars().filter(|v| v.is_encrypted()) {
            items.push((
                v.name.clone(),
                crypto::decrypt(&old_key, &v.name, &v.value)?,
            ));
        }
        files.push((file, items));
    }

    let new_pw = session::prompt_new_password()?;
    let new_salt = crypto::new_salt_b64()?;
    let params = crypto::KdfParams::default();
    let new_key = crypto::derive_key(&new_pw, &new_salt, params)?;

    let mut count = 0;
    for (file, items) in files.iter_mut() {
        for (name, pt) in items.iter() {
            file.set_value(name, &crypto::encrypt(&new_key, name, pt)?)?;
            count += 1;
        }
        file.save()?;
    }

    let stored = (!a.no_store).then(|| new_pw.to_string());
    let written = config::save(&config::Config::new(new_salt, params, stored))?;
    note!(
        "{} password changed; re-encrypted {count} item(s) across {} file(s) {}",
        green("✓"),
        env.files.len(),
        dim(&written.display().to_string())
    );
    if env.files.is_empty() {
        note!(
            "{} no files given: old ciphertext in other .env files can no longer be decrypted",
            yellow("⚠️")
        );
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn direct_and_explicit_run_preserve_child_arguments() {
        for argv in [
            vec!["localenvx", "-e", "first.vars", "echo", "-e", "child"],
            vec![
                "localenvx",
                "run",
                "-e",
                "first.vars",
                "echo",
                "-e",
                "child",
            ],
            vec![
                "localenvx",
                "run",
                "-e",
                "first.vars",
                "--",
                "echo",
                "-e",
                "child",
            ],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.env.files, vec![PathBuf::from("first.vars")]);
            let cmd = match cli.cmd.unwrap() {
                Cmd::Run(args) => args.cmd,
                Cmd::External(cmd) => cmd,
                _ => panic!("expected run"),
            };
            assert_eq!(cmd, vec!["echo", "-e", "child"]);
        }
    }

    #[test]
    fn builtin_names_and_boolean_quiet() {
        assert!(matches!(
            Cli::try_parse_from(["x", "get", "KEY"]).unwrap().cmd,
            Some(Cmd::Get(_))
        ));
        assert!(matches!(
            Cli::try_parse_from(["x", "--", "get", "KEY"]).unwrap().cmd,
            Some(Cmd::External(_))
        ));
        assert_eq!(
            Cli::try_parse_from(["x", "-q=false", "echo"])
                .unwrap()
                .quiet,
            Some(false)
        );
        assert!(Cli::try_parse_from(["x", "-p", "KEY"]).is_err());
    }
}
