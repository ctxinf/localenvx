---
name: localenvx
description: A local encrypted .env manager.
---

# localenvx usage guide

A local encrypted .env manager.

Run `localenvx --skill` to print this bundled guide; no configuration is needed.
Use `localenvx --help` or `localenvx manage COMMAND --help` for flags.

## Workflow

```bash
# Generate a random key in the local credential file.
localenvx manage init
# Encrypt a value in .env without putting it in shell history.
printf '%s' 'example-secret' | localenvx manage set API_TOKEN --enc --stdin -y
# Decrypt into the child environment only.
localenvx run -- node app.js
# Use project credentials instead of user credentials.
localenvx manage init --config-file .localenvx/config.toml
```

By default, the nearest `.localenvx/config.toml` found from the current directory upward wins over the user config. `init` defaults to creating user credentials; use `--config-file .localenvx/config.toml` to initialize project credentials. `--config-file PATH` wins over both; `LOCALENVX_CONFIG_DIR` overrides the user config directory, and `XDG_CONFIG_HOME` overrides its base on all platforms. Project initialization rejects existing encrypted env files to avoid losing access to user-encrypted values.

For agents: use `manage ls` and `manage status` to inspect metadata. `manage get`, `manage dec`, and the local UI reveal secrets; only use them when requested. Keep credentials and encrypted env files out of commits unless the user explicitly chooses otherwise. Encryption protects stored values, not against a process that can read credentials or invoke this tool.

## Platforms

Linux, macOS and Windows; native executables and Cargo installation. Unix replaces the process and preserves signals; Windows waits for the child and forwards its exit code. Executables run directly, without shell interpretation. Use `sh -c`, `cmd /C`, or `powershell -Command` explicitly for shell built-ins. Unix files use mode 0600; Windows uses inherited filesystem ACLs, so keep the credential directory private.

## File format

blacklist (**the default** — what you get with no tag at all: everything encrypted, `@PLAIN` to opt out):

```bash
# @PLAIN
LOG_LEVEL=debug
API_TOKEN=encrypted:v1:BHe9lUzNq4oS0tX...
```

whitelist (must be declared explicitly: plaintext by default, `@ENC` to encrypt):

```bash
# @localenvx-mode:whitelist

NODE_ENV=development

# @ENC
DATABASE_URL=encrypted:v1:BFc4vRxLq8mN2pQ...
```

- The mode tag only takes effect **before the first variable**; later occurrences are ignored, and having both tags is an error.
- `@ENC` / `@PLAIN` apply only to the **immediately following variable** (no blank line in between); having both is an error.
- Rewriting a file preserves comments, blank lines, order, quote style, the `export ` prefix and inline comments.

## Commands

| Command | Description |
|---|---|
| `manage status` | Show version, credentials and file metadata |
| `manage init [--config-file PATH]` | Generate a random credential key file; never overwrite existing credentials |
| `[OPTIONS] [--] CMD [ARGS...]` | Direct run; arguments after CMD pass through untouched |
| `run [OPTIONS] [--] CMD [ARGS...]` | Explicit run, sharing the direct entry's resolution and execution |
| `manage set NAME [VALUE] [--enc\|--plain] [--stdin] [-e FILE]... [-y]` | Write to every selected file after confirmation |
| `manage get NAME [OPTIONS]` | Print the final environment value, using the same resolution as run; missing names are errors |
| `manage ls [-e FILE]... [--all]` | List key names and encryption status only; --all scans the current directory |
| `manage enc [-k GLOB]... [-e FILE]` | Bulk-encrypt one file according to its mode |
| `manage dec -k GLOB... [-e FILE]` | Decrypt one file to plaintext |
| `manage ui [--port N] [--strict-port]` | Local web UI |

Options belong to each command and are not global; place them after the command (for example, `localenvx manage get -e .env KEY`). Run may be omitted.

All environment-file selectors use `-e`; omitted selectors use `.env`. `--config-file PATH` selects the credential config for run and management commands except status and ls, including `init` and `ui`, ahead of the existing default config location. Run and get still require initialization, including for plaintext input. Debug does not.

`manage ls` accepts only `-e FILE` (repeatable) or `--all`, plus help. `--all` lists `.env` and `.env.*` files in the current directory in filename order, excluding temporary `.tmp` files and directories, without recursion. It conflicts with `-e`. No credentials are loaded.

Run/get options:

- Repeat `-e FILE` to select files. Default precedence is **process environment > first file > later files**. With `-o` / `--override`, it is **last file > earlier files > process environment**. Within each file the last duplicate wins.
- Repeat `-v NAME=value` to inject temporary values after expansion. They have highest priority, repeated names use the last value, empty values are rejected, and values stay literal. `-v` has no effect on persistent edits.
- `-c [ENVIRONMENT]` selects `<base>.<environment>.local`, `<base>.local`, `<base>.<environment>`, then `<base>`, in that priority order for each `-e` base. Bare `-c` selects `<base>.local`, then `<base>`. Use `-c -- COMMAND` to disambiguate a bare cascade flag from its optional environment argument. Cascade and override conflict.
- Expansion is enabled over the merged environment, including decrypted values and inherited variables; `--no-expand` leaves references literal. Temporary `-v` values are applied afterward.
- Run-only `--debug` prints the candidate paths and temporary variable object, including their values, then exits without reading files, loading credentials, or executing a command.
- Run/get are quiet by default. `--quiet=false` / `-q=false` enables a summary on stderr; `--quiet` / `-q` silences it. Explicit flags take precedence over `LOCALENVX_QUIET=1|true|0|false`. Missing cascade candidates all together still produce a warning.

A missing default or explicitly selected file is an error. Missing cascade candidates are skipped; when all candidates are missing, a warning is printed and execution continues using the process environment plus `-v`. Other read errors remain errors.

Only winning ciphertext is decrypted. Values needed by expansion count as effective: if `REF=$SECRET` and `-v SECRET=temporary` is supplied, REF expands from SECRET's loaded value before the temporary replacement. Completely unused ciphertext shadowed by files, the process environment, or `-v` does not need a key.

Only `run` and `manage` are reserved at the root. `localenvx manage get NAME` reads a variable; `localenvx get NAME` runs an executable named get. Use `localenvx -- manage` to run an executable named manage. `-p` is unsupported.

Set prints target paths and affected key names before prompting `[Y/n]`. Enter confirms; `n` cancels; `-y` / `--yes` skips the prompt. Noninteractive input requires `-y`, also when stdin is reserved for a set value. Set updates the last occurrence and removes earlier duplicates. Delete variables directly from the file when needed. All changes are prepared and validated before saving. Each file is replaced atomically; a multi-file edit is not a filesystem transaction.

## Credentials and backups

`manage init` creates a version 2 TOML credential file containing a randomly generated 256-bit key:

```toml
version = 2
key = "<base64-encoded 32-byte key>"
```

No passwords, prompts, password environment variables, salt, or password derivation are used. `passwd`, `--password-stdin`, `--no-store`, and `--force` are removed. Initialization refuses to overwrite an existing credential file. Unix permissions are 0600. Back up this file securely: possession of it allows decryption, and losing it makes the encrypted values unrecoverable.

To move to another machine, copy both the encrypted `.env` and its credential file. On Unix, run `chmod 600` on the copied credential file. Select it with `--config-file PATH` or place it at the project's `.localenvx/config.toml` or the user config location. Do not generate a replacement key for existing ciphertext.

## Migrating password-based credentials

Version 1 credential files are rejected without changes. Use the previous release with the original credentials to decrypt existing files first. Back up and move aside the old credential file, run `manage init`, then encrypt the plaintext files using the new credential file. A previous password change that left ciphertext untouched requires the credential backup from before that change; a newly generated key cannot recover those values.

## Encryption

```
encrypted:v1:<base64url( nonce[24] ‖ ciphertext ‖ tag[16] )>
```

XChaCha20-Poly1305 with the random 256-bit key loaded directly from the credential file. The **AAD binds the variable name**, so ciphertext pasted onto another key fails to decrypt. The stderr summary never prints values.

## Known trade-offs

The credential file contains the encryption key. Keep it private and out of version control. For agents, restrict access to credentials and commands that reveal values:
```
Read(**/.env*)
Read(**/.config/localenvx/**)
Bash(localenvx manage get:*)
Bash(localenvx manage ui:*)
```
