# CLI end-to-end coverage

Run `cargo test --locked --test cli`. These tests launch the compiled binary,
use isolated temporary projects and synthetic credentials, and check exit status,
stdout/stderr, persisted files, and downstream command behavior.

The existing CI runs this suite on Linux, macOS, and Windows, on both x64 and
ARM64. Password interaction tests run on all six runners: Unix uses PTYs, and Windows
uses ConPTY through the pinned pywinpty adapter installed by CI. Windows ARM64
uses x64 Python under emulation to drive the native ARM64 CLI. Only Unix signal,
shell-specific expansion, and confirmation PTY tests remain `cfg(unix)`.

| Area | End-to-end assertions |
| --- | --- |
| init | Explicit/project configuration, stdin password, overwrite protection, existing encrypted project protection |
| encrypt | Blacklist/whitelist policies, ENC/PLAIN directives, repeated key globs, empty values, idempotence, unchanged unselected values/comments |
| decrypt | Explicit selection required, partial/all glob matches, plaintext policy after decryption, unmatched keys, wrong password, corrupt ciphertext, no partial writes on decryption failure |
| passwd | Corrupt later file leaves earlier files/config unchanged; automated Unix PTY / Windows ConPTY: multi-file rotation, stored password, no-store, old password rejection, mismatch rollback |
| set/rm | Multiple files, duplicate keys, confirmation, stdin values, empty values, invalid/conflicting arguments, missing keys, Unicode and space-containing paths |
| get/run | File/process/temporary precedence, lazy expansion/decryption, no-expand, native subprocess environment and exit codes on every platform, all three invocation styles; Unix signals |
| credentials | Explicit/project/user selection, password stdin over environment/config, empty/wrong password, no password leakage in tested failures |
| list/status | File/key/mode/encryption reports, no values or credentials, invalid/missing files, list without usable credentials |
| help/skill/debug/quiet | Credential-free help/guide/debug, output consistency, quiet override |

Run Windows terminal tests locally with Python 3.12 and
`python -m pip install --only-binary=:all: pywinpty==3.0.2`, then
`cargo test --locked --test cli`. Set `LOCALENVX_TEST_PYTHON` to an absolute Python
executable path if it is not on PATH. Missing terminal dependencies fail the tests
rather than skipping them. CI has separate unit/CLI steps and a job timeout;
terminal adapters also enforce per-process deadlines.

Windows ACL behavior, Web UI HTTP/browser interactions, installers/upgrades,
and exhaustive filesystem failure injection
remain outside this suite. These tests do not establish transactional safety for
write failures across multiple files.
