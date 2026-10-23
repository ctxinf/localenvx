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
