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
    about = "本地开发用的加密环境变量管理工具",
    long_about = "磁盘上没有明文机密：.env 里的敏感值以 XChaCha20-Poly1305 密文保存，\n只在 `localenvx run` 时解密并通过 environ 传给子进程。"
)]
struct Cli {
    /// 从 stdin 读取密码（优先级最高）
    #[arg(long, global = true)]
    password_stdin: bool,
    /// 完全静音 stderr 摘要
    #[arg(long, short, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成 salt、设置密码并写入 config
    Init(InitArgs),
    /// 加载 .env 并执行子进程（不经 shell）
    Run(RunArgs),
    /// 写入变量（按当前模式决定是否加密）
    Set(SetArgs),
    /// 读取单个变量的值到 stdout
    Get(GetArgs),
    /// 列出 key 名与加密状态（不显示 value）
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// 删除变量
    Rm(RmArgs),
    /// 批量加密现有明文
    #[command(visible_alias = "enc")]
    Encrypt(BulkArgs),
    /// 解密为明文（慎用：明文会落盘）
    #[command(visible_alias = "dec")]
    Decrypt(BulkArgs),
    /// 改密码，并用新密码重加密指定文件
    Passwd(PasswdArgs),
    /// 本地 Web UI（127.0.0.1，前台进程，Ctrl-C 退出）
    Ui(UiArgs),
}

#[derive(Args)]
struct InitArgs {
    /// 不把密码写进 config（之后每次用 LOCALENVX_PASSWORD 或手输）
    #[arg(long)]
    no_store: bool,
    /// 覆盖已存在的 config（会导致旧密文无法解密）
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct RunArgs {
    /// env 文件，优先级从左到右递增；缺省为 .env
    files: Vec<PathBuf>,
    /// 让文件覆盖真实进程环境变量（默认相反）
    #[arg(long)]
    r#override: bool,
    /// 要执行的命令，写在 `--` 之后
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Args)]
struct FileArg {
    /// 目标文件，缺省为 .env
    #[arg(short, long, default_value = ".env")]
    file: PathBuf,
}

#[derive(Args)]
struct SetArgs {
    name: String,
    value: Option<String>,
    #[command(flatten)]
    file: FileArg,
    /// 强制明文
    #[arg(long, conflicts_with = "enc")]
    plain: bool,
    /// 强制加密
    #[arg(long)]
    enc: bool,
    /// 从 stdin 读取 value（避免进 shell history）
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
    /// 变量名或 glob，可重复；encrypt 缺省为「该文件模式下应加密的全部变量」（blacklist 下即全部）
    #[arg(short = 'k', long = "key")]
    keys: Vec<String>,
}

#[derive(Args)]
struct PasswdArgs {
    /// 需要重加密的文件；不传则只换密码（旧密文将无法解密）
    files: Vec<PathBuf>,
    /// 不把新密码写进 config
    #[arg(long)]
    no_store: bool,
}

#[derive(Args)]
struct UiArgs {
    /// 起始端口，占用则依次 +1（上限 +99）
    #[arg(long, default_value_t = 27500)]
    port: u16,
    /// 端口被占用时直接失败，不顺延
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
            "{} 已存在；用 --force 覆盖（旧密文将无法解密）",
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
        green("✓ 已初始化"),
        dim(&written.display().to_string())
    );
    if a.no_store {
        note!("  密码未保存：之后请用 LOCALENVX_PASSWORD 或交互输入");
    } else {
        note!(
            "  {}",
            yellow("密码已明文存在 config 里（0600）——建议另存一份到 1Password，忘了不可恢复")
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
        note!("{} 找不到 {}，已跳过", yellow("⚠️"), m.display());
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
                "{} 进程环境里已有 {}，文件值未生效（--override 可反转）",
                dim("·"),
                e.name
            );
        }
    }
    exec(cmd, &a.cmd[0])
}

/// 直接 execve 替换自身：不经 shell，退出码与信号天然透传。
fn exec(mut cmd: std::process::Command, program: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::Error::new(err).context(format!("无法执行 {program}")))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("无法执行 {program}"))?;
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
            "  {}  {} 覆盖了 {} 的 {}",
            yellow("⚠️"),
            to.display(),
            from.display(),
            name
        );
    }
}

// ── F5 增删改查 ───────────────────────────────────────────────────────────────

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
        (Some(_), true) => bail!("--stdin 与位置参数 VALUE 只能二选一"),
        (None, false) => bail!("缺少 VALUE（或用 --stdin 从标准输入读取）"),
    };

    let mut file = open_or_new(&a.file.file)?;
    let want_enc = if a.enc {
        Some(true)
    } else if a.plain {
        Some(false)
    } else {
        None
    };
    // 先落位，再按「有效意图」决定是否加密。
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
        .with_context(|| format!("{}: 没有变量 {}", a.file.file.display(), a.name))?;
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
                bail!("找不到文件: {}", path.display());
            }
            note!("{} 找不到 {}", yellow("⚠️"), path.display());
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
    note!("{} 已删除 {}", green("✓"), a.name);
    Ok(())
}

/// 按文件顺序选出匹配任一 glob 的变量名。
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
        // 空手而归时说清原因，不然看起来像 bug。
        note!(
            "{} {} 是 {} 模式，没有需要加密的变量",
            dim("·"),
            a.file.file.display(),
            file.mode.as_str()
        );
        if a.keys.is_empty() && file.mode == envfile::Mode::Whitelist {
            note!(
                "  whitelist 下只加密标了 {} 的变量；指定 {} 或在首个变量前写 {} 可改为默认加密",
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
        "{} 已加密 {} 项: {}",
        green("✓"),
        names.len(),
        names.join(" ")
    );
    Ok(())
}

fn cmd_decrypt(a: &BulkArgs, password_stdin: bool) -> Result<()> {
    if a.keys.is_empty() {
        bail!("decrypt 必须显式指定 -k（明文会落盘，不做全量默认）");
    }
    let mut file = EnvFile::load(&a.file.file)?;
    let names: Vec<String> = selected(&file, &a.keys)
        .into_iter()
        .filter(|n| file.get(n).unwrap().is_encrypted())
        .collect();
    if names.is_empty() {
        note!("{} 没有匹配到密文变量", dim("·"));
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
        "{} 已解密 {} 项到明文: {}",
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
        _ => session::prompt_password("当前密码: ")?,
    };
    let old_key = crypto::derive_key(&old_pw, &cfg.kdf.salt, cfg.params())?;

    // 先把所有密文解出来，全部成功才换密码——避免半途失败留下混合状态。
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
        "{} 密码已更换；重加密 {count} 项，涉及 {} 个文件 {}",
        green("✓"),
        a.files.len(),
        dim(&written.display().to_string())
    );
    if a.files.is_empty() {
        note!("{} 没传文件：其它 .env 里的旧密文已无法解密", yellow("⚠️"));
    }
    Ok(())
}
