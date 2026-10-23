//! End-to-end checks use isolated synthetic .env.example fixtures only.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "localenvx-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let project = Self(path);
        std::fs::write(project.0.join("config.toml"), "version = 1\npassword = 'synthetic-test-password'\n[kdf]\nalgo = 'argon2id'\nsalt = 'MTIzNDU2Nzg5MGFiY2RlZg=='\nm = 8\nt = 1\np = 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                project.0.join("config.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        project
    }
    fn fixture(&self, directory: &str, content: &str) -> PathBuf {
        let directory = self.0.join(directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(".env.example");
        std::fs::write(&path, content).unwrap();
        path
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_localenvx"));
        cmd.current_dir(&self.0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        cmd.arg("--config-file").arg(self.0.join("config.toml"));
        cmd
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn text(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn final_environment_priority_expansion_and_get_match_run() {
    let p = Project::new();
    let first = p.fixture("first", "K=earlier\nK=first\nURL=$K/${MISSING:-ok}\n");
    let second = p.fixture("second", "K=second\n");
    for (extra, expected) in [(vec![], "system"), (vec!["-o"], "second")] {
        let output = p
            .command()
            .env("K", "system")
            .args(["-e", path(&first), "-e", path(&second)])
            .args(&extra)
            .args(["get", "K"])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), format!("{expected}\n"));
        assert!(output.stderr.is_empty());
    }
    let output = p.run(&["-e", path(&first), "-e", path(&second), "get", "URL"]);
    success(&output);
    assert_eq!(text(&output), "first/ok\n");
    #[cfg(unix)]
    for entry in [vec!["run", "--"], vec!["--"], vec![]] {
        let output = p
            .command()
            .args(["-e", path(&first), "-e", path(&second)])
            .args(entry)
            .args(["/bin/sh", "-c", "printf '%s\\n' \"$URL\""])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), "first/ok\n");
    }
    let output = p.run(&["-e", path(&first), "--no-expand", "get", "URL"]);
    success(&output);
    assert_eq!(text(&output), "$K/${MISSING:-ok}\n");
    let output = p.run(&["-e", path(&first), "-v", "K=temporary", "get", "URL"]);
    success(&output);
    assert_eq!(text(&output), "first/ok\n");
    let output = p.run(&["-e", path(&first), "-v", "K=$literal", "get", "K"]);
    success(&output);
    assert_eq!(text(&output), "$literal\n");
}

#[test]
fn shadowed_corrupt_ciphertext_is_never_decrypted() {
    let p = Project::new();
    let first = p.fixture("first", "K=good\n");
    let bad = p.fixture("bad", "K=encrypted:v1:invalid\n");
    for args in [
        vec!["-e", path(&first), "-e", path(&bad), "get", "K"],
        vec!["-e", path(&bad), "-e", path(&first), "-o", "get", "K"],
        vec!["-e", path(&bad), "-v", "K=good", "get", "K"],
    ] {
        let output = p.run(&args);
        success(&output);
        assert_eq!(text(&output), "good\n");
    }
    let output = p
        .command()
        .env("K", "system")
        .args(["-e", path(&bad), "get", "K"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "system\n");
    assert!(!p.run(&["-e", path(&bad), "get", "K"]).status.success());
}

#[test]
fn missing_files_cascade_and_read_free_debug() {
    let p = Project::new();
    assert!(!p.run(&["get", "PATH"]).status.success());
    let output = p.run(&["-e", "absent", "-c", "test", "get", "PATH"]);
    success(&output);
    assert_eq!(text(&output), "/usr/bin:/bin\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("warn:"));
    assert!(!p.run(&["-c", "test", "-o", "get", "PATH"]).status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_localenvx"))
        .current_dir(&p.0)
        .env_clear()
        .args([
            "--config-file",
            "missing-config",
            "--debug",
            "-e",
            "absent",
            "-v",
            "MODE=test",
        ])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "[ 'absent' ]\n{ MODE: 'test' }\n");
}

#[test]
fn multi_file_edits_require_confirmation_and_remove_duplicates() {
    let p = Project::new();
    let first = p.fixture("first", "A=one\nA=two\n");
    let second = p.fixture("second", "A=other\n");
    let args = [
        "-e",
        path(&first),
        "-e",
        path(&second),
        "set",
        "A",
        "updated",
        "--plain",
    ];
    assert!(!p.run(&args).status.success());
    assert_eq!(std::fs::read_to_string(&first).unwrap(), "A=one\nA=two\n");
    let output = p.command().args(args).arg("-y").output().unwrap();
    success(&output);
    for file in [&first, &second] {
        let output = p.run(&["-e", path(file), "get", "A"]);
        success(&output);
        assert_eq!(text(&output), "updated\n");
        assert_eq!(
            std::fs::read_to_string(file).unwrap().matches("A=").count(),
            1
        );
    }
    let output = p.run(&["-e", path(&first), "-e", path(&second), "rm", "A", "-y"]);
    success(&output);
    for file in [&first, &second] {
        assert!(!std::fs::read_to_string(file).unwrap().contains("A="));
    }
}

#[test]
fn encrypted_dependencies_expand_before_temporary_values() {
    let p = Project::new();
    let file = p.fixture(
        "first",
        "# @localenvx-mode:whitelist\nREF=${SECRET:-${MISSING:-fallback}}\n",
    );
    let output = p.run(&[
        "-e",
        path(&file),
        "set",
        "SECRET",
        "decrypted",
        "--enc",
        "-y",
    ]);
    success(&output);
    let output = p.run(&["-e", path(&file), "-v", "SECRET=temporary", "get", "REF"]);
    success(&output);
    assert_eq!(text(&output), "decrypted\n");
}

#[cfg(unix)]
#[test]
fn child_exit_codes_and_signals_pass_through() {
    use std::os::unix::process::ExitStatusExt;
    let p = Project::new();
    let file = p.fixture("first", "K=value\n");
    let output = p.run(&["-e", path(&file), "--", "/bin/sh", "-c", "exit 37"]);
    assert_eq!(output.status.code(), Some(37));
    let output = p.run(&["-e", path(&file), "--", "/bin/sh", "-c", "kill -TERM $$"]);
    assert_eq!(output.status.signal(), Some(15));
}

#[cfg(unix)]
#[test]
fn terminal_confirmation_accepts_enter_and_declines_no() {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    let p = Project::new();
    let file = p.fixture("first", "A=old\n");
    for (answer, expected) in [("n\n", "old"), ("\n", "new")] {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let child = p
            .command()
            .args(["-e", path(&file), "set", "A", "new", "--plain"])
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        master.write_all(answer.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        success(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("[Y/n]"));
        let output = p.run(&["-e", path(&file), "get", "A"]);
        success(&output);
        assert_eq!(text(&output), format!("{expected}\n"));
    }
}

#[test]
fn explicit_config_initialization_and_password_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    let p = Project::new();
    let file = p.fixture("first", "");
    let mut child = p
        .command()
        .args(["init", "--force"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-new-password\n")
        .unwrap();
    success(&child.wait_with_output().unwrap());
    let mut child = p
        .command()
        .args([
            "--password-stdin",
            "-e",
            path(&file),
            "set",
            "A",
            "test",
            "--enc",
            "-y",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-new-password\n")
        .unwrap();
    success(&child.wait_with_output().unwrap());
    let output = p.run(&["-e", path(&file), "get", "A"]);
    success(&output);
    assert_eq!(text(&output), "test\n");
}

#[test]
fn quiet_false_overrides_the_quiet_environment_and_run_debug_needs_no_command() {
    let p = Project::new();
    let file = p.fixture("first", "K=value\n");
    let output = p
        .command()
        .env("LOCALENVX_QUIET", "true")
        .args(["-q=false", "-e", path(&file), "get", "K"])
        .output()
        .unwrap();
    success(&output);
    assert!(!output.stderr.is_empty());
    let output = p.run(&["run", "--debug", "-e", "absent"]);
    success(&output);
    assert_eq!(text(&output), "[ 'absent' ]\n{}\n");
}

#[cfg(unix)]
#[test]
fn unused_conditional_branches_do_not_decrypt_temporary_replacements() {
    let p = Project::new();
    for (i, expression, expected) in [
        (0, "${GOOD:-$BAD}", "ok"),
        (1, "${GOOD-$BAD}", "ok"),
        (2, "${MISSING:+$BAD}", ""),
        (3, "${MISSING+$BAD}", ""),
        (4, "${GOOD:-${BAD:-fallback}}", "ok"),
        (5, "${MISSING:+${BAD:-fallback}}", ""),
        (6, "${GOOD:+${MISSING:-ok}}", "ok"),
    ] {
        // A replaced key must stay lazy regardless of its position in file order.
        for before in [true, false] {
            let bad = "BAD=encrypted:v1:invalid\n";
            let content = format!("GOOD=ok\nK={expression}\n");
            let content = if before {
                format!("{bad}{content}")
            } else {
                format!("{content}{bad}")
            };
            let file = p.fixture(&format!("case-{i}-{before}"), &content);
            for command in [
                vec!["get", "K"],
                vec!["run", "--", "/bin/sh", "-c", "printf '%s\\n' \"$K\""],
            ] {
                let output = p
                    .command()
                    .args(["-e", path(&file), "-v", "BAD=temporary"])
                    .args(command)
                    .output()
                    .unwrap();
                success(&output);
                assert_eq!(text(&output), format!("{expected}\n"), "{expression}");
            }
        }
    }
}

#[test]
fn selected_conditional_branches_still_require_decryption() {
    let p = Project::new();
    for (i, expression) in [
        "${MISSING:-$BAD}",
        "${GOOD:+$BAD}",
        "${MISSING:-${GOOD:+$BAD}}",
    ]
    .iter()
    .enumerate()
    {
        let file = p.fixture(
            &format!("bad-{i}"),
            &format!("GOOD=ok\nBAD=encrypted:v1:invalid\nK={expression}\n"),
        );
        let output = p.run(&["-e", path(&file), "-v", "BAD=temporary", "get", "K"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("BAD:"));
    }
    let file = p.fixture(
        "encrypted",
        "# @localenvx-mode:whitelist\nK=${SECRET:-${BAD:-fallback}}\nBAD=encrypted:v1:invalid\n",
    );
    success(&p.run(&[
        "-e",
        path(&file),
        "set",
        "SECRET",
        "decrypted",
        "--enc",
        "-y",
    ]));
    let output = p.run(&[
        "-e",
        path(&file),
        "-v",
        "BAD=temporary",
        "-v",
        "SECRET=temporary",
        "get",
        "K",
    ]);
    success(&output);
    assert_eq!(text(&output), "decrypted\n");
    // The condition must use decrypted emptiness, not ciphertext non-emptiness.
    success(&p.run(&["-e", path(&file), "set", "SECRET", "", "--enc", "-y"]));
    assert!(
        !p.run(&["-e", path(&file), "-v", "BAD=temporary", "get", "K"])
            .status
            .success()
    );
}

#[test]
fn process_environment_dependencies_are_lazy_too() {
    let p = Project::new();
    let file = p.fixture("first", "GOOD=ok\nBAD=encrypted:v1:invalid\n");
    let output = p
        .command()
        .env("K", "${GOOD:-$BAD}")
        .args(["-e", path(&file), "-v", "BAD=temporary", "get", "K"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "ok\n");
    let output = p
        .command()
        .env("K", "$BAD")
        .args([
            "-e",
            path(&file),
            "-v",
            "BAD=temporary",
            "-v",
            "K=replaced",
            "get",
            "K",
        ])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "replaced\n");
    let output = p.run(&[
        "-e",
        path(&file),
        "--no-expand",
        "-v",
        "BAD=temporary",
        "get",
        "GOOD",
    ]);
    success(&output);
    assert_eq!(text(&output), "ok\n");
}

#[test]
fn user_credentials_win_and_project_credentials_are_a_fallback() {
    let p = Project::new();
    let file = p.fixture("nested", "");
    let project_dir = p.0.join(".localenvx");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::copy(p.0.join("config.toml"), project_dir.join("config.toml")).unwrap();
    // Deliberately invalid user config must fail rather than silently falling back.
    let user_dir = p.0.join("user");
    std::fs::create_dir_all(&user_dir).unwrap();
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_localenvx"));
        cmd.current_dir(file.parent().unwrap())
            .env_clear()
            .env("LOCALENVX_CONFIG_DIR", &user_dir)
            .args(["-e", path(&file)]);
        cmd
    };
    let output = command()
        .args(["set", "A", "synthetic", "--enc", "-y"])
        .output()
        .unwrap();
    success(&output);
    let output = command().args(["get", "A"]).output().unwrap();
    success(&output);
    assert_eq!(text(&output), "synthetic\n");
    std::fs::copy(p.0.join("config.toml"), user_dir.join("config.toml")).unwrap();
    std::fs::write(user_dir.join("config.toml"), "invalid config").unwrap();
    let output = command().args(["get", "A"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse"));
    // Explicit selection takes precedence even when the user config is invalid.
    let output = command()
        .args([
            "--config-file",
            path(&project_dir.join("config.toml")),
            "get",
            "A",
        ])
        .output()
        .unwrap();
    success(&output);
}

#[test]
fn project_initialization_is_explicit_and_does_not_replace_user_credentials() {
    use std::io::Write;
    use std::process::Stdio;
    let p = Project::new();
    let user_dir = p.0.join("user");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_localenvx"));
    let mut child = cmd
        .current_dir(&p.0)
        .env_clear()
        .env("LOCALENVX_CONFIG_DIR", &user_dir)
        .args(["init", "--project"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-project-password\n")
        .unwrap();
    success(&child.wait_with_output().unwrap());
    assert!(p.0.join(".localenvx/config.toml").is_file());
    assert!(!user_dir.exists());
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn status_reports_configuration_and_suggestions_without_values() {
    let p = Project::new();
    let file = p.fixture(
        "",
        "A=synthetic-private-plain\nB=encrypted:v1:synthetic-private-ciphertext\n",
    );
    // No -e: verify discovery in the isolated project directory.
    let output = p.run(&["status"]);
    success(&output);
    assert!(output.stderr.is_empty());
    let report = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Status:",
        "Active config:",
        "initialized",
        ".env.example",
        "2 variables, 1 encrypted, 1 plaintext",
        "localenvx --help",
        "localenvx run -- <command>",
        "localenvx init --project",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    assert!(!report.contains("synthetic-private"));
    assert!(!report.contains("synthetic-test-password"));
    // Invalid configurations must not expose parser diagnostics containing secrets.
    std::fs::write(p.0.join("config.toml"), "synthetic-config-secret").unwrap();
    let output = p.run(&["-e", path(&file), "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("unusable"));
    assert!(report.contains("Suggestions:"));
    assert!(!report.contains("synthetic-config-secret"));
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    let output = p.run(&["-e", path(&file), "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("not generated"));
    assert!(report.contains("1 encrypted"));
}

#[test]
fn status_tolerates_missing_and_invalid_environment_files() {
    let p = Project::new();
    let file = p.fixture(
        "",
        "# @localenvx-mode:whitelist\n# @localenvx-mode:blacklist\nA=synthetic-private-value\n",
    );
    let output = p.run(&["-e", path(&file), "-e", "missing.vars", "--quiet", "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    success(&output);
    assert!(report.contains("unreadable or invalid"));
    assert!(report.contains("missing.vars: not found"));
    assert!(report.contains("localenvx --help"));
    assert!(!report.contains("synthetic-private-value"));
}

#[test]
fn missing_command_is_brief_and_help_matches_help_flag() {
    let p = Project::new();
    let output = p.run(&[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing command"));
    assert!(stderr.contains("--help"));
    assert!(!stderr.contains("Status:"));
    assert!(!stderr.contains("Active config:"));
    assert_eq!(stderr.lines().count(), 1);

    // Help must work with no usable credentials and must not inspect env files.
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    let flag = p.run(&["--help"]);
    let command = p.run(&["help"]);
    success(&flag);
    success(&command);
    assert_eq!(command.stdout, flag.stdout);
    assert!(command.stderr.is_empty());
    assert!(text(&command).contains("status"));
}
