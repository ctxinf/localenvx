mod config;
mod crypto;
mod envfile;
mod load;
mod session;
mod term;
mod ui;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::envfile::EnvFile;
use crate::session::Session;
use crate::term::{cyan, dim, green, note, yellow};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "localenvx",
    version,
    about = "Encrypted environment-variable manager for local development",
    long_about = "No plaintext secrets on disk: sensitive values in .env are stored as XChaCha20-Poly1305\nciphertext, decrypted only during `localenvx run` and passed to the child process via environ."
)]
struct Cli {
    /// Read the password from stdin (highest precedence)
    #[arg(long, global = true)]
    password_stdin: bool,
    /// Silence the stderr summary entirely
    #[arg(long, short, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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

#[derive(Args)]
struct RunArgs {
    /// env files, precedence increasing left to right; defaults to .env
    files: Vec<PathBuf>,
    /// Let files override the real process environment (the default is the opposite)
    #[arg(long)]
    r#override: bool,
    /// The command to run, written after `--`
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Args)]
struct FileArg {
    /// Target file; defaults to .env
    #[arg(short, long, default_value = ".env")]
    file: PathBuf,
}

#[derive(Args)]
struct SetArgs {
    name: String,
    value: Option<String>,
    #[command(flatten)]
    file: FileArg,
    /// Force plaintext
    #[arg(long, conflicts_with = "enc")]
    plain: bool,
    /// Force encryption
    #[arg(long)]
    enc: bool,
    /// Read the value from stdin (keeps it out of shell history)
    #[arg(long)]
    stdin: bool,
}

#[derive(Args)]
struct GetArgs {
    name: String,
    #[command(flatten)]
    file: FileArg,
}

#[derive(Args)]
struct ListArgs {
    files: Vec<PathBuf>,
}

#[derive(Args)]
struct RmArgs {
    name: String,
    #[command(flatten)]
    file: FileArg,
}

#[derive(Args)]
struct BulkArgs {
    #[command(flatten)]
    file: FileArg,
    /// Variable name or glob, repeatable; encrypt defaults to "every variable this file's mode says should be encrypted" (all of them under blacklist)
    #[arg(short = 'k', long = "key")]
    keys: Vec<String>,
}

#[derive(Args)]
struct PasswdArgs {
    /// Files to re-encrypt; with none given only the password changes (old ciphertext becomes undecryptable)
    files: Vec<PathBuf>,
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
    if cli.quiet {
        term::set_quiet(true);
    }
    if let Err(e) = dispatch(&cli) {
        eprintln!("{} {e:#}", term::paint("31;1", "error:"));
        std::process::exit(1);
    }
}

fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Init(a) => cmd_init(a),
        Cmd::Run(a) => cmd_run(a, cli.password_stdin),
        Cmd::Set(a) => cmd_set(a, cli.password_stdin),
        Cmd::Get(a) => cmd_get(a, cli.password_stdin),
        Cmd::List(a) => cmd_list(a),
        Cmd::Rm(a) => cmd_rm(a),
        Cmd::Encrypt(a) => cmd_encrypt(a, cli.password_stdin),
        Cmd::Decrypt(a) => cmd_decrypt(a, cli.password_stdin),
        Cmd::Passwd(a) => cmd_passwd(a),
        Cmd::Ui(a) => ui::serve(a.port, a.strict_port, cli.password_stdin),
    }
}

// ── F6 init ──────────────────────────────────────────────────────────────────

fn cmd_init(a: &InitArgs) -> Result<()> {
    let path = config::config_path()?;
    if path.exists() && !a.force {
        bail!(
            "{} already exists; pass --force to overwrite (old ciphertext becomes undecryptable)",
            path.display()
        );
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

fn cmd_run(a: &RunArgs, password_stdin: bool) -> Result<()> {
    let (paths, explicit) = load::default_paths(&a.files);
    let mut sess = Session::open(password_stdin)?;
    let loaded = load::load_files(&mut sess, &paths, explicit)?;

    for m in &loaded.missing {
        note!("{} {} not found, skipped", yellow("⚠️"), m.display());
    }
    print_summary(&loaded);

    let mut cmd = std::process::Command::new(&a.cmd[0]);
    cmd.args(&a.cmd[1..]);
    for e in &loaded.entries {
        let in_env = std::env::var_os(&e.name).is_some();
        if !in_env || a.r#override {
            cmd.env(&e.name, e.value.as_str());
        } else {
            note!(
                "{} {} is already in the process environment; the file value was not applied (--override flips this)",
                dim("·"),
                e.name
            );
        }
    }
    exec(cmd, &a.cmd[0])
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

fn open_or_new(path: &std::path::Path) -> Result<EnvFile> {
    if path.exists() {
        EnvFile::load(path)
    } else {
        Ok(EnvFile::empty_at(path))
    }
}

fn cmd_set(a: &SetArgs, password_stdin: bool) -> Result<()> {
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

    let mut file = open_or_new(&a.file.file)?;
    let want_enc = if a.enc {
        Some(true)
    } else if a.plain {
        Some(false)
    } else {
        None
    };
    // Insert the line first, then let the effective intent decide whether to encrypt.
    file.upsert(&a.name, "", want_enc)?;
    let encrypt = want_enc.unwrap_or_else(|| file.should_encrypt(&a.name));
    let stored = if encrypt {
        let mut sess = Session::open(password_stdin)?;
        crypto::encrypt(sess.key()?, &a.name, &value)?
    } else {
        value
    };
    file.set_value(&a.name, &stored)?;
    file.save()?;
    note!(
        "{} {} → {} ({})",
        green("✓"),
        a.name,
        a.file.file.display(),
        if encrypt { "encrypted" } else { "plain" }
    );
    Ok(())
}

fn cmd_get(a: &GetArgs, password_stdin: bool) -> Result<()> {
    let file = EnvFile::load(&a.file.file)?;
    let var = file
        .get(&a.name)
        .with_context(|| format!("{}: no variable named {}", a.file.file.display(), a.name))?;
    if var.is_encrypted() {
        let mut sess = Session::open(password_stdin)?;
        let pt = crypto::decrypt(sess.key()?, &a.name, &var.value)?;
        println!("{}", *pt);
    } else {
        println!("{}", var.value);
    }
    Ok(())
}

fn cmd_list(a: &ListArgs) -> Result<()> {
    let (paths, explicit) = load::default_paths(&a.files);
    for path in &paths {
        if !path.exists() {
            if explicit {
                bail!("file not found: {}", path.display());
            }
            note!("{} {} not found", yellow("⚠️"), path.display());
            continue;
        }
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

fn cmd_rm(a: &RmArgs) -> Result<()> {
    let mut file = EnvFile::load(&a.file.file)?;
    file.remove(&a.name)?;
    file.save()?;
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

fn cmd_encrypt(a: &BulkArgs, password_stdin: bool) -> Result<()> {
    let mut file = EnvFile::load(&a.file.file)?;
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
            a.file.file.display(),
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

fn cmd_decrypt(a: &BulkArgs, password_stdin: bool) -> Result<()> {
    if a.keys.is_empty() {
        bail!(
            "decrypt requires an explicit -k (plaintext lands on disk, so there is no bulk default)"
        );
    }
    let mut file = EnvFile::load(&a.file.file)?;
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

fn cmd_passwd(a: &PasswdArgs) -> Result<()> {
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
    for path in &a.files {
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
        a.files.len(),
        dim(&written.display().to_string())
    );
    if a.files.is_empty() {
        note!(
            "{} no files given: old ciphertext in other .env files can no longer be decrypted",
            yellow("⚠️")
        );
    }
    Ok(())
}
