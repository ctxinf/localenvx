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
        std::fs::write(
            project.0.join("config.toml"),
            "version = 2\nkey = 'MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY='\n",
        )
        .unwrap();
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
        cmd.env("LOCALENVX_CONFIG_DIR", &self.0);
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
            .args(["manage", "get", "-q"])
            .args(["-e", path(&first), "-e", path(&second)])
            .args(&extra)
            .args(["K"])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), format!("{expected}\n"));
        assert!(output.stderr.is_empty());
    }
    let output = p.run(&[
        "manage",
        "get",
        "-e",
        path(&first),
        "-e",
        path(&second),
        "URL",
    ]);
    success(&output);
    assert_eq!(text(&output), "first/ok\n");
    #[cfg(unix)]
    for entry in [vec!["run", "--"], vec!["--"], vec![]] {
        let output = p
            .command()
            .args(entry.first().filter(|x| **x == "run"))
            .args(["-e", path(&first), "-e", path(&second)])
            .args(entry.iter().filter(|x| **x != "run"))
            .args(["/bin/sh", "-c", "printf '%s\\n' \"$URL\""])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), "first/ok\n");
    }
    let output = p.run(&["manage", "get", "-e", path(&first), "--no-expand", "URL"]);
    success(&output);
    assert_eq!(text(&output), "$K/${MISSING:-ok}\n");
    let output = p.run(&[
        "manage",
        "get",
        "-e",
        path(&first),
        "-v",
        "K=temporary",
        "URL",
    ]);
    success(&output);
    assert_eq!(text(&output), "first/ok\n");
    let output = p.run(&["manage", "get", "-e", path(&first), "-v", "K=$literal", "K"]);
    success(&output);
    assert_eq!(text(&output), "$literal\n");
}

#[test]
fn shadowed_corrupt_ciphertext_is_never_decrypted() {
    let p = Project::new();
    let first = p.fixture("first", "K=good\n");
    let bad = p.fixture("bad", "K=encrypted:v1:invalid\n");
    for args in [
        vec!["manage", "get", "-e", path(&first), "-e", path(&bad), "K"],
        vec![
            "manage",
            "get",
            "-e",
            path(&bad),
            "-e",
            path(&first),
            "-o",
            "K",
        ],
        vec!["manage", "get", "-e", path(&bad), "-v", "K=good", "K"],
    ] {
        let output = p.run(&args);
        success(&output);
        assert_eq!(text(&output), "good\n");
    }
    let output = p
        .command()
        .env("K", "system")
        .args(["manage", "get", "-e", path(&bad), "K"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "system\n");
    assert!(
        !p.run(&["manage", "get", "-e", path(&bad), "K"])
            .status
            .success()
    );
}

#[test]
fn missing_files_cascade_and_read_free_debug() {
    let p = Project::new();
    assert!(!p.run(&["manage", "get", "PATH"]).status.success());
    let output = p.run(&["manage", "get", "-e", "absent", "-c", "test", "PATH"]);
    success(&output);
    assert_eq!(text(&output), "/usr/bin:/bin\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("warn:"));
    assert!(
        !p.run(&["manage", "get", "-c", "test", "-o", "PATH"])
            .status
            .success()
    );
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
        "manage",
        "set",
        "-e",
        path(&first),
        "-e",
        path(&second),
        "A",
        "updated",
        "--plain",
    ];
    assert!(!p.run(&args).status.success());
    assert_eq!(std::fs::read_to_string(&first).unwrap(), "A=one\nA=two\n");
    let output = p.command().args(args).arg("-y").output().unwrap();
    success(&output);
    for file in [&first, &second] {
        let output = p.run(&["manage", "get", "-e", path(file), "A"]);
        success(&output);
        assert_eq!(text(&output), "updated\n");
        assert_eq!(
            std::fs::read_to_string(file).unwrap().matches("A=").count(),
            1
        );
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
        "manage",
        "set",
        "-e",
        path(&file),
        "SECRET",
        "decrypted",
        "--enc",
        "-y",
    ]);
    success(&output);
    let output = p.run(&[
        "manage",
        "get",
        "-e",
        path(&file),
        "-v",
        "SECRET=temporary",
        "REF",
    ]);
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
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let child = p
            .command()
            .args(["manage", "set", "-e", path(&file), "A", "new", "--plain"])
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        master.write_all(answer.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        success(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("[Y/n]"));
        let output = p.run(&["manage", "get", "-e", path(&file), "A"]);
        success(&output);
        assert_eq!(text(&output), format!("{expected}\n"));
    }
}

#[test]
fn init_creates_random_credentials_without_input_and_never_overwrites() {
    let p = Project::new();
    let file = p.fixture("first", "A=secret\n");
    let first = p.0.join("new/first.toml");
    let second = p.0.join("new/second.toml");
    for config in [&first, &second] {
        success(&p.run(&["manage", "init", "--config-file", path(config)]));
        let text = std::fs::read_to_string(config).unwrap();
        let cfg: toml::Value = text.parse().unwrap();
        assert_eq!(cfg["version"].as_integer(), Some(2));
        assert_eq!(cfg["key"].as_str().unwrap().len(), 44);
        assert!(cfg.get("password").is_none());
        assert!(cfg.get("kdf").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(config).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        failure(
            &p.run(&["manage", "init", "--config-file", path(config)]),
            "already exists",
        );
        assert_eq!(std::fs::read_to_string(config).unwrap(), text);
    }
    assert_ne!(
        std::fs::read(&first).unwrap(),
        std::fs::read(&second).unwrap()
    );
    success(&p.run(&[
        "manage",
        "enc",
        "--config-file",
        path(&first),
        "-e",
        path(&file),
    ]));
    let ciphertext = std::fs::read(&file).unwrap();
    failure(
        &p.run(&[
            "manage",
            "get",
            "--config-file",
            path(&second),
            "-e",
            path(&file),
            "A",
        ]),
        "decryption failed",
    );
    assert_eq!(std::fs::read(&file).unwrap(), ciphertext);
    assert_eq!(
        text(&p.run(&[
            "manage",
            "get",
            "--config-file",
            path(&first),
            "-e",
            path(&file),
            "A"
        ])),
        "secret\n"
    );
    failure(
        &p.run(&["manage", "init", "--force", "--config-file", path(&first)]),
        "unexpected argument",
    );
}

#[test]
fn concurrent_init_never_replaces_the_winning_key() {
    let p = Project::new();
    let config = p.0.join("concurrent.toml");
    let args = ["manage", "init", "--config-file", path(&config)];
    let first = p
        .command()
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let second = p
        .command()
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let a = first.wait_with_output().unwrap();
    let b = second.wait_with_output().unwrap();
    assert_ne!(a.status.success(), b.status.success());
    let original = std::fs::read(&config).unwrap();
    let file = p.fixture("", "A=concurrent-secret\n");
    success(&p.run(&[
        "manage",
        "enc",
        "--config-file",
        path(&config),
        "-e",
        path(&file),
    ]));
    success(&p.run(&[
        "manage",
        "get",
        "--config-file",
        path(&config),
        "-e",
        path(&file),
        "A",
    ]));
    assert_eq!(std::fs::read(&config).unwrap(), original);
}

#[test]
fn get_reports_read_files_and_winning_source_unless_quiet() {
    let p = Project::new();
    let first = p.fixture("first", "K=first\n");
    let second = p.fixture("second", "K=second\n");
    for (options, expected, source) in [
        (vec![], "first\n", path(&first)),
        (vec!["-o"], "second\n", path(&second)),
        (
            vec!["-v", "K=temporary"],
            "temporary\n",
            "temporary variable (-v)",
        ),
    ] {
        for quiet in [false, true] {
            let mut args = vec!["manage", "get", "-e", path(&first), "-e", path(&second)];
            args.extend(&options);
            if quiet {
                args.push("-q");
            }
            args.push("K");
            let output = p.run(&args);
            success(&output);
            assert_eq!(text(&output), expected);
            let details = String::from_utf8_lossy(&output.stderr);
            if quiet {
                assert!(details.is_empty(), "{details}");
            } else {
                assert!(details.contains(path(&first)), "{details}");
                assert!(details.contains(path(&second)), "{details}");
                let mut files = vec![path(&first), path(&second)];
                if !options.contains(&"-o") {
                    files.reverse();
                }
                let expected = files
                    .iter()
                    .map(|file| {
                        format!(
                            "{file}  {}\n",
                            if *file == source {
                                "effective"
                            } else {
                                "ineffective"
                            }
                        )
                    })
                    .collect::<String>();
                assert_eq!(details, expected);
            }
        }
    }
    let output = p
        .command()
        .env("K", "inherited")
        .args(["manage", "get", "-e", path(&first), "K"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "inherited\n");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("{}  ineffective\n", path(&first))
    );
}

#[test]
fn quiet_false_overrides_the_quiet_environment_and_run_debug_needs_no_command() {
    let p = Project::new();
    let file = p.fixture("first", "K=value\n");
    let output = p
        .command()
        .env("LOCALENVX_QUIET", "true")
        .args(["manage", "get", "-q=false", "-e", path(&file), "K"])
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
                vec!["manage", "get", "K"],
                vec!["run", "--", "/bin/sh", "-c", "printf '%s\\n' \"$K\""],
            ] {
                let output = p
                    .command()
                    .args(&command[..if command[0] == "manage" { 2 } else { 1 }])
                    .args(["-e", path(&file), "-v", "BAD=temporary"])
                    .args(&command[if command[0] == "manage" { 2 } else { 1 }..])
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
        let output = p.run(&[
            "manage",
            "get",
            "-e",
            path(&file),
            "-v",
            "BAD=temporary",
            "K",
        ]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("BAD:"));
    }
    let file = p.fixture(
        "encrypted",
        "# @localenvx-mode:whitelist\nK=${SECRET:-${BAD:-fallback}}\nBAD=encrypted:v1:invalid\n",
    );
    success(&p.run(&[
        "manage",
        "set",
        "-e",
        path(&file),
        "SECRET",
        "decrypted",
        "--enc",
        "-y",
    ]));
    let output = p.run(&[
        "manage",
        "get",
        "-e",
        path(&file),
        "-v",
        "BAD=temporary",
        "-v",
        "SECRET=temporary",
        "K",
    ]);
    success(&output);
    assert_eq!(text(&output), "decrypted\n");
    // The condition must use decrypted emptiness, not ciphertext non-emptiness.
    success(&p.run(&[
        "manage",
        "set",
        "-e",
        path(&file),
        "SECRET",
        "",
        "--enc",
        "-y",
    ]));
    assert!(
        !p.run(&[
            "manage",
            "get",
            "-e",
            path(&file),
            "-v",
            "BAD=temporary",
            "K"
        ])
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
        .args([
            "manage",
            "get",
            "-e",
            path(&file),
            "-v",
            "BAD=temporary",
            "K",
        ])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "ok\n");
    let output = p
        .command()
        .env("K", "$BAD")
        .args([
            "manage",
            "get",
            "-e",
            path(&file),
            "-v",
            "BAD=temporary",
            "-v",
            "K=replaced",
            "K",
        ])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "replaced\n");
    let output = p.run(&[
        "manage",
        "get",
        "-e",
        path(&file),
        "--no-expand",
        "-v",
        "BAD=temporary",
        "GOOD",
    ]);
    success(&output);
    assert_eq!(text(&output), "ok\n");
}

#[test]
fn project_credentials_win_and_user_credentials_are_a_fallback() {
    let p = Project::new();
    let file = p.fixture("nested", "");
    let project_dir = p.0.join(".localenvx");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::copy(p.0.join("config.toml"), project_dir.join("config.toml")).unwrap();
    // Project credentials take precedence even when user credentials are invalid.
    let user_dir = p.0.join("user");
    std::fs::create_dir_all(&user_dir).unwrap();
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_localenvx"));
        cmd.current_dir(file.parent().unwrap())
            .env_clear()
            .env("LOCALENVX_CONFIG_DIR", &user_dir);
        cmd
    };
    let output = command()
        .args([
            "manage",
            "set",
            "-e",
            path(&file),
            "A",
            "synthetic",
            "--enc",
            "-y",
        ])
        .output()
        .unwrap();
    success(&output);
    let output = command()
        .args(["manage", "get", "-e", path(&file), "A"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "synthetic\n");
    std::fs::copy(p.0.join("config.toml"), user_dir.join("config.toml")).unwrap();
    std::fs::write(user_dir.join("config.toml"), "invalid config").unwrap();
    let output = command()
        .args(["manage", "get", "-e", path(&file), "A"])
        .output()
        .unwrap();
    success(&output);
    assert_eq!(text(&output), "synthetic\n");
    // Without project credentials, the invalid user configuration is reported.
    std::fs::remove_file(project_dir.join("config.toml")).unwrap();
    let output = command()
        .args(["manage", "get", "-e", path(&file), "A"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse"));
    std::fs::copy(p.0.join("config.toml"), user_dir.join("config.toml")).unwrap();
    success(
        &command()
            .args(["manage", "get", "-e", path(&file), "A"])
            .output()
            .unwrap(),
    );
    std::fs::copy(p.0.join("config.toml"), project_dir.join("config.toml")).unwrap();
    std::fs::write(project_dir.join("config.toml"), "invalid config").unwrap();
    let output = command()
        .args(["manage", "get", "-e", path(&file), "A"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse"));
    // An explicit config overrides an invalid project configuration.
    let output = command()
        .args([
            "manage",
            "get",
            "-e",
            path(&file),
            "--config-file",
            path(&user_dir.join("config.toml")),
            "A",
        ])
        .output()
        .unwrap();
    success(&output);
    std::fs::write(user_dir.join("config.toml"), "invalid config").unwrap();
    std::fs::copy(p.0.join("config.toml"), project_dir.join("config.toml")).unwrap();
    // Explicit selection takes precedence even when the user config is invalid.
    let output = command()
        .args([
            "manage",
            "get",
            "-e",
            path(&file),
            "--config-file",
            path(&project_dir.join("config.toml")),
            "A",
        ])
        .output()
        .unwrap();
    success(&output);
}

#[test]
fn project_initialization_is_explicit_and_does_not_replace_user_credentials() {
    let p = Project::new();
    let original = std::fs::read(p.0.join("config.toml")).unwrap();
    success(&p.run(&["manage", "init", "--config-file", ".localenvx/config.toml"]));
    assert!(p.0.join(".localenvx/config.toml").is_file());
    assert_eq!(std::fs::read(p.0.join("config.toml")).unwrap(), original);
    failure(
        &p.run(&["manage", "init", "--config-file", ".localenvx/config.toml"]),
        "already exists",
    );
}

#[test]
fn status_reports_configuration_and_suggestions_without_values() {
    let p = Project::new();
    let _file = p.fixture(
        "",
        "A=synthetic-private-plain\nB=encrypted:v1:synthetic-private-ciphertext\n",
    );
    // No -e: verify discovery in the isolated project directory.
    let output = p.run(&["manage", "status"]);
    success(&output);
    assert!(output.stderr.is_empty());
    let report = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Status:",
        "User config:",
        "(✅Active)",
        "📦 Project config: not existed",
        ".env.example",
        "2 variables, 1 encrypted, 1 plaintext",
        "localenvx --help",
        "localenvx run -- <command>",
        "localenvx manage init --config-file .localenvx/config.toml",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    assert!(!report.contains("Active config:"));
    assert!(!report.contains("Directory:"));
    assert!(!report.contains("synthetic-private"));
    assert!(!report.contains("MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY="));
    // Invalid configurations must not expose parser diagnostics containing secrets.
    std::fs::write(p.0.join("config.toml"), "synthetic-config-secret").unwrap();
    let output = p.run(&["manage", "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("unusable"));
    assert!(report.contains("Suggestions:"));
    assert!(!report.contains("synthetic-config-secret"));
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    let output = p.run(&["manage", "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("User config: not existed"));
    assert!(report.contains("1 encrypted"));
}

#[test]
fn status_tolerates_missing_and_invalid_environment_files() {
    let p = Project::new();
    let _file = p.fixture(
        "",
        "# @localenvx-mode:whitelist\n# @localenvx-mode:blacklist\nA=synthetic-private-value\n",
    );
    let output = p.run(&["manage", "status"]);
    let report = String::from_utf8_lossy(&output.stdout);
    success(&output);
    assert!(report.contains("unreadable or invalid"));
    assert!(report.contains(".env: not found"));
    assert!(report.contains("localenvx --help"));
    assert!(!report.contains("synthetic-private-value"));
}

#[test]
fn status_has_no_business_options() {
    let p = Project::new();
    let output = p.run(&["manage", "status", "--help"]);
    success(&output);
    assert!(text(&output).contains("-h, --help"));
    for option in [
        "--password-stdin",
        "--config-file",
        "--project",
        "--quiet",
        "-e",
        "-c",
    ] {
        assert!(
            !text(&output)
                .lines()
                .any(|line| line.trim_start().starts_with(option)),
            "{option}"
        );
        assert!(
            !p.run(&["manage", "status", option]).status.success(),
            "{option}"
        );
    }
}

#[test]
fn startup_and_help_show_version_and_examples() {
    let p = Project::new();
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    for args in [vec![], vec!["--help"], vec!["manage", "status"]] {
        let output = p.run(&args);
        success(&output);
        assert!(text(&output).contains(concat!("localenvx v", env!("CARGO_PKG_VERSION"))));
        assert!(output.stderr.is_empty());
    }
    let output = p.run(&[]);
    assert_eq!(text(&output).lines().count(), 2);
    assert!(text(&output).contains("use localenvx --help"));
    let output = p.run(&["--help"]);
    assert!(text(&output).contains("Examples:"));
    assert!(!text(&output).contains("--project"));
    assert!(text(&output).contains("nearest .localenvx/config.toml"));
    assert!(text(&output).contains("Init defaults to user config"));
    assert!(text(&output).contains("--no-expand"));
    assert!(!text(&output).contains("--port"));
    let output = p.run(&["manage", "get", "--help"]);
    success(&output);
    assert!(text(&output).contains("--no-expand"));
    assert!(!text(&output).contains("--debug"));
    for args in [
        vec!["manage", "set", "--no-expand"],
        vec!["manage", "ui", "-e", "x"],
        vec!["manage", "rm"],
        vec!["manage", "list"],
        vec!["manage", "encrypt"],
        vec!["manage", "decrypt"],
        vec!["manage", "help"],
    ] {
        assert!(!p.run(&args).status.success(), "{args:?}");
    }
}

#[test]
fn project_initialization_rejects_existing_user_encryption() {
    let p = Project::new();
    let file = p.fixture("nested/deep", "");
    success(&p.run(&[
        "manage",
        "set",
        "-e",
        path(&file),
        "SECRET",
        "synthetic",
        "--enc",
        "-y",
    ]));
    let original = std::fs::read(&file).unwrap();
    {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_localenvx"));
        cmd.current_dir(&p.0)
            .env_clear()
            .env("LOCALENVX_CONFIG_DIR", &p.0)
            .args(["manage", "init", "--config-file", ".localenvx/config.toml"]);
        let output = cmd.output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("contains encrypted values"), "{stderr}");
        assert!(!stderr.contains("new password:"));
        assert!(!p.0.join(".localenvx/config.toml").exists());
        assert_eq!(std::fs::read(&file).unwrap(), original);
    }
    success(&p.run(&["manage", "get", "-e", path(&file), "SECRET"]));
}

#[test]
fn bundled_guide_needs_no_credentials_or_env_files() {
    let p = Project::new();
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    let output = p.run(&["--skill"]);
    success(&output);
    assert_eq!(text(&output), include_str!("../SKILL.md"));
    assert!(output.stderr.is_empty());
}

#[test]
fn native_child_runs_and_exit_codes_pass_through_on_every_platform() {
    let p = Project::new();
    let file = p.fixture("native", "K=synthetic\n");
    let executable = env!("CARGO_BIN_EXE_localenvx");
    let output = p.run(&["run", "-e", path(&file), "--", executable, "--version"]);
    success(&output);
    assert!(text(&output).starts_with("localenvx "));
    let output = p.run(&[
        "run",
        "-e",
        path(&file),
        "--",
        executable,
        "--invalid-option",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

fn failure(output: &Output, message: &str) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        text(output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "expected {message:?}: {stderr}");
}

fn input(mut command: Command, value: &[u8]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(value).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn bulk_encryption_respects_modes_and_is_idempotent() {
    let p = Project::new();
    for (mode, marked, unmarked) in [("whitelist", "ENC", false), ("blacklist", "PLAIN", true)] {
        let file = p.fixture(mode, &format!("# @localenvx-mode:{mode}\n# keep this comment\n# @{marked}\nMARKED=marked-value\nOTHER=other-value\n"));
        success(&p.run(&["manage", "enc", "-e", path(&file)]));
        let stored = std::fs::read_to_string(&file).unwrap();
        assert!(stored.contains("# keep this comment"));
        assert_eq!(stored.contains("OTHER=encrypted:v1:"), unmarked);
        assert_eq!(stored.contains("MARKED=encrypted:v1:"), !unmarked);
        for (key, value) in [("MARKED", "marked-value"), ("OTHER", "other-value")] {
            let output = p.run(&["manage", "get", "-e", path(&file), key]);
            success(&output);
            assert_eq!(text(&output), format!("{value}\n"));
        }
        success(&p.run(&["manage", "enc", "-e", path(&file)]));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), stored);
    }
}

#[test]
fn bulk_globs_round_trip_and_decrypt_requires_explicit_selection() {
    let p = Project::new();
    let file = p.fixture("", "# @localenvx-mode:whitelist\nAPI_TOKEN=secret-one\nDB_TOKEN=secret-two\nPUBLIC=visible\nEMPTY=\n");
    success(&p.run(&[
        "manage",
        "enc",
        "-e",
        path(&file),
        "-k",
        "*_TOKEN",
        "-k",
        "EMPTY",
    ]));
    let encrypted = std::fs::read(&file).unwrap();
    let stored = String::from_utf8_lossy(&encrypted);
    assert_eq!(stored.matches("encrypted:v1:").count(), 3);
    assert!(!stored.contains("secret-one"));
    assert!(!stored.contains("secret-two"));
    assert!(stored.contains("PUBLIC=visible"));
    failure(&p.run(&["manage", "dec", "-e", path(&file)]), "explicit -k");
    assert_eq!(std::fs::read(&file).unwrap(), encrypted);
    success(&p.run(&["manage", "dec", "-e", path(&file), "-k", "API_*"]));
    let stored = std::fs::read_to_string(&file).unwrap();
    assert!(stored.contains("API_TOKEN=secret-one"));
    assert!(stored.contains("DB_TOKEN=encrypted:v1:"));
    success(&p.run(&["manage", "dec", "-e", path(&file), "-k", "*"]));
    let plain = std::fs::read(&file).unwrap();
    assert!(!String::from_utf8_lossy(&plain).contains("encrypted:v1:"));
    success(&p.run(&["manage", "enc", "-e", path(&file)]));
    assert_eq!(
        std::fs::read(&file).unwrap(),
        plain,
        "decrypted keys must remain plaintext by policy"
    );
    success(&p.run(&["manage", "dec", "-e", path(&file), "-k", "MISSING*"]));
    assert_eq!(std::fs::read(&file).unwrap(), plain);
    let output = p.run(&["manage", "get", "-e", path(&file), "EMPTY"]);
    success(&output);
    assert_eq!(text(&output), "\n");
}

#[test]
fn failed_decryption_preserves_files_and_config() {
    let p = Project::new();
    let first = p.fixture("first", "A=synthetic-secret\n");
    success(&p.run(&["manage", "enc", "-e", path(&first)]));
    let good = std::fs::read(&first).unwrap();
    let config = std::fs::read(p.0.join("config.toml")).unwrap();
    let wrong = p.0.join("wrong.toml");
    success(&p.run(&["manage", "init", "--config-file", path(&wrong)]));
    failure(
        &p.run(&[
            "manage",
            "dec",
            "--config-file",
            path(&wrong),
            "-e",
            path(&first),
            "-k",
            "*",
        ]),
        "decryption failed",
    );
    assert_eq!(std::fs::read(&first).unwrap(), good);
    assert_eq!(std::fs::read(p.0.join("config.toml")).unwrap(), config);
    // Even a successfully decrypted earlier key must not be saved on later failure.
    let mut mixed = good.clone();
    mixed.extend_from_slice(b"B=encrypted:v1:invalid\n");
    std::fs::write(&first, &mixed).unwrap();
    assert!(
        !p.run(&["manage", "dec", "-e", path(&first), "-k", "*"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(&first).unwrap(), mixed);
}

#[test]
fn list_never_decrypts_or_prints_values_and_lists_each_file() {
    let p = Project::new();
    let first = p.fixture("first", "# @localenvx-mode:whitelist\nPLAIN=synthetic-private-value\nSECRET=encrypted:v1:synthetic-corrupt-ciphertext\n");
    let second = p.fixture("second", "OTHER=another-private-value\n");
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    let output = p.run(&["manage", "ls", "-e", path(&first), "-e", path(&second)]);
    success(&output);
    let report = text(&output);
    for expected in [
        path(&first),
        path(&second),
        "whitelist",
        "PLAIN",
        "SECRET",
        "OTHER",
        "enc",
        "plain",
    ] {
        assert!(report.contains(expected), "{report}");
    }
    for secret in [
        "synthetic-private",
        "synthetic-corrupt",
        "another-private",
        "encrypted:v1:",
    ] {
        assert!(!report.contains(secret), "{report}");
    }
    assert!(output.stderr.is_empty());
    assert!(!p.run(&["manage", "ls", "-e", "missing"]).status.success());
}

#[test]
fn stdin_values_unicode_paths_and_literal_values_round_trip() {
    let p = Project::new();
    let file = p.fixture("spaces and 中文", "# preserved\n");
    let mut command = p.command();
    command.args([
        "manage",
        "set",
        "-e",
        path(&file),
        "SECRET",
        "--stdin",
        "--enc",
        "-y",
    ]);
    success(&input(
        command,
        "中文 value with = and # and 'quotes'\r\n".as_bytes(),
    ));
    let output = p.run(&["manage", "get", "-e", path(&file), "SECRET"]);
    success(&output);
    assert_eq!(text(&output), "中文 value with = and # and 'quotes'\n");
    assert!(
        !std::fs::read_to_string(&file)
            .unwrap()
            .contains("中文 value")
    );
    let mut command = p.command();
    command.args([
        "manage",
        "set",
        "-e",
        path(&file),
        "EMPTY",
        "--stdin",
        "--plain",
        "-y",
    ]);
    success(&input(command, b""));
    assert_eq!(
        text(&p.run(&["manage", "get", "-e", path(&file), "EMPTY"])),
        "\n"
    );
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("# preserved")
    );
}

#[test]
fn invalid_set_arguments_never_modify_files() {
    let p = Project::new();
    let file = p.fixture("", "A=original\n");
    for (args, message) in [
        (vec!["manage", "set", "A"], "missing VALUE"),
        (
            vec!["manage", "set", "A", "value", "--stdin", "-y"],
            "mutually exclusive",
        ),
        (
            vec!["manage", "set", "A", "value", "--plain", "--enc", "-y"],
            "cannot be used",
        ),
        (vec!["manage", "set", "A", "--stdin", "--plain"], "pass -y"),
        (vec!["manage", "get", "MISSING"], "no variable named"),
    ] {
        let output = p
            .command()
            .args(args)
            .args(["-e", path(&file)])
            .output()
            .unwrap();
        failure(&output, message);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "A=original\n");
    }
}

#[test]
fn passwords_and_rotation_are_removed_and_environment_cannot_change_key() {
    let p = Project::new();
    let file = p.fixture("", "A=secret\n");
    success(&p.run(&["manage", "enc", "-e", path(&file)]));
    let ciphertext = std::fs::read(&file).unwrap();
    let credentials = std::fs::read(p.0.join("config.toml")).unwrap();
    for value in ["", "wrong-password"] {
        let output = p
            .command()
            .env("LOCALENVX_PASSWORD", value)
            .args(["manage", "get", "-e", path(&file), "A"])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), "secret\n");
    }
    for args in [
        vec!["manage", "passwd"],
        vec!["manage", "get", "--password-stdin", "A"],
        vec!["manage", "init", "--no-store"],
    ] {
        assert!(!p.run(&args).status.success());
    }
    assert_eq!(std::fs::read(&file).unwrap(), ciphertext);
    assert_eq!(std::fs::read(p.0.join("config.toml")).unwrap(), credentials);
}

#[test]
fn legacy_and_invalid_credentials_are_rejected_without_leaking_or_changing_them() {
    let p = Project::new();
    let file = p.fixture("", "A=secret\n");
    for (config, expected) in [
        (
            "version = 1\npassword = 'synthetic-legacy-secret'\n",
            "legacy password-based credential file",
        ),
        (
            "version = 2\nkey = 'synthetic-invalid-secret'\n",
            "credential key",
        ),
        (
            "version = 2\nkey = 'synthetic-parse-secret' broken\n",
            "failed to parse",
        ),
        ("version = 99\n", "unsupported config version"),
    ] {
        std::fs::write(p.0.join("config.toml"), config).unwrap();
        let output = p.run(&["manage", "get", "-e", path(&file), "A"]);
        failure(&output, expected);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-"));
        failure(&p.run(&["manage", "init"]), "already exists");
        assert_eq!(
            std::fs::read_to_string(p.0.join("config.toml")).unwrap(),
            config
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "A=secret\n");
    }
}

#[test]
fn bulk_commands_reject_multiple_files_and_missing_files() {
    let p = Project::new();
    let first = p.fixture("first", "A=original\n");
    let second = p.fixture("second", "B=other\n");
    for command in ["enc", "dec"] {
        failure(
            &p.run(&[
                "manage",
                command,
                "-e",
                path(&first),
                "-e",
                path(&second),
                "-k",
                "*",
            ]),
            "single -e file",
        );
        assert!(
            !p.run(&["manage", command, "-e", "missing", "-k", "*"])
                .status
                .success()
        );
    }
    assert_eq!(std::fs::read_to_string(first).unwrap(), "A=original\n");
    assert_eq!(std::fs::read_to_string(second).unwrap(), "B=other\n");
}

#[test]
fn native_child_receives_decrypted_environment_on_every_platform() {
    let p = Project::new();
    let file = p.fixture("", "SECRET=child-secret\n");
    success(&p.run(&["manage", "enc", "-e", path(&file)]));
    for entry in [vec!["run", "--"], vec!["--"], vec![]] {
        let output = p
            .command()
            .args(entry.first().filter(|x| **x == "run"))
            .args(["-e", path(&file)])
            .args(entry.iter().filter(|x| **x != "run"))
            .args([
                env!("CARGO_BIN_EXE_localenvx"),
                "manage",
                "get",
                "--config-file",
                path(&p.0.join("config.toml")),
                "-e",
                path(&file),
                "-v",
                "SECRET=child-override",
                "SECRET",
            ])
            .output()
            .unwrap();
        success(&output);
        assert_eq!(text(&output), "child-override\n");
        // An empty file ensures the nested CLI can only get SECRET by inheritance.
        let empty = p.fixture("empty-child", "");
        let output = p.run(&[
            "run",
            "-e",
            path(&file),
            "--",
            env!("CARGO_BIN_EXE_localenvx"),
            "manage",
            "get",
            "--config-file",
            path(&p.0.join("config.toml")),
            "-e",
            path(&empty),
            "SECRET",
        ]);
        success(&output);
        assert_eq!(text(&output), "child-secret\n");
    }
}

#[test]
fn ls_all_discovers_only_env_files_without_credentials_or_values() {
    let p = Project::new();
    std::fs::remove_file(p.0.join("config.toml")).unwrap();
    for (name, content) in [
        (".env", "BASE=synthetic-private-value\n"),
        (
            ".env.local",
            "SECRET=encrypted:v1:synthetic-corrupt-ciphertext\n",
        ),
        (".env.production", "PRODUCTION=hidden\n"),
        (".env.local.tmp", "SKIP_TMP=hidden\n"),
        ("other.env", "SKIP_OTHER=hidden\n"),
    ] {
        std::fs::write(p.0.join(name), content).unwrap();
    }
    std::fs::create_dir(p.0.join(".env.directory")).unwrap();
    p.fixture("nested", "SKIP_NESTED=hidden\n");
    let output = p.run(&["manage", "ls", "--all"]);
    success(&output);
    let report = text(&output);
    for name in ["BASE", "SECRET", "PRODUCTION"] {
        assert!(report.contains(name));
    }
    for private in [
        "synthetic-private-value",
        "synthetic-corrupt-ciphertext",
        "hidden",
        "SKIP_",
        ".tmp",
        ".env.directory",
        "nested",
    ] {
        assert!(!report.contains(private), "{report}");
    }
    assert!(report.find(".env  ").unwrap() < report.find(".env.local").unwrap());
    assert!(report.find(".env.local").unwrap() < report.find(".env.production").unwrap());
    let output = p.run(&["manage", "ls"]);
    success(&output);
    assert!(text(&output).contains("BASE"));
    assert!(!text(&output).contains("SECRET"));
}

#[test]
fn ls_options_are_limited_and_all_handles_empty_directory() {
    let p = Project::new();
    let output = p.run(&["manage", "ls", "--all"]);
    success(&output);
    assert!(text(&output).contains("No .env files found"));
    failure(
        &p.run(&["manage", "ls", "--all", "-e", "file"]),
        "cannot be used",
    );
    let output = p.run(&["manage", "ls", "--help"]);
    success(&output);
    assert!(text(&output).contains("--all"));
    for option in ["--quiet", "--config-file", "--password-stdin", "--project"] {
        assert!(!text(&output).contains(option));
        assert!(!p.run(&["manage", "ls", option]).status.success());
    }
}
