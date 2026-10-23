# CLI end-to-end coverage

Run `cargo test --locked --test cli`. These tests launch the compiled binary,
use isolated temporary projects and synthetic credentials, and check exit status,
stdout/stderr, persisted files, and downstream command behavior.

Pushing a new `v*` tag starts the release workflow, which calls the test workflow
before building and publishing release assets. Branch pushes and pull requests do
not trigger CI. The test workflow runs this suite on Linux, macOS, and Windows, on both x64 and
ARM64. Init and credential operations require no terminal or password input. Unix signal,
shell-specific expansion, and confirmation PTY tests remain `cfg(unix)`.

| Area | End-to-end assertions |
| --- | --- |
| init | Explicit/project configuration, random keys, noninteractive initialization, key permissions, overwrite protection, existing encrypted project protection |
| encrypt | Blacklist/whitelist policies, ENC/PLAIN directives, repeated key globs, empty values, idempotence, unchanged unselected values/comments |
| decrypt | Explicit selection required, partial/all glob matches, plaintext policy after decryption, unmatched keys, wrong credential file, corrupt ciphertext, no partial writes on decryption failure |
| set | Multiple files, duplicate keys, confirmation, stdin values, empty values, invalid/conflicting arguments, missing keys, Unicode and space-containing paths |
| get/run | File/process/temporary precedence, lazy expansion/decryption, no-expand, native subprocess environment and exit codes on every platform, all three invocation styles; Unix signals |
| credentials | Explicit/project/user selection, ignored password environment, removed password flags/command, rejected legacy/malformed credentials, no key leakage in tested failures |
| list/status | File/key/mode/encryption reports, no values or credentials, invalid/missing files, list without usable credentials |
| help/skill/debug/quiet | Credential-free help/guide/debug, output consistency, quiet override |

Windows ACL behavior, Web UI HTTP/browser interactions, installers/upgrades,
and exhaustive filesystem failure injection
remain outside this suite. These tests do not establish transactional safety for
write failures across multiple files.
