# localenvx

Encrypted environment-variable manager for local development. **No plaintext secrets on disk**, so a coding agent that happens to `grep` or read files gets nothing.

```bash
cargo build --release              # target/release/localenvx
scripts/install-local.sh           # build and install into ~/.local/bin (BIN_DIR= to change, --uninstall to remove)
```

## Quick start

```bash
localenvx init                                   # generate a salt, set the password (stored in the config by default)
localenvx set OPENAI_API_KEY "sk-..." --enc -y      # write encrypted into .env
localenvx set PORT 3000 --plain -y                # plaintext
localenvx list                                   # key names and encryption status only
localenvx run -e .env.local -e .env.base -- npm dev    # decrypt, then execve the child process
localenvx ui                                     # http://127.0.0.1:27500/
```

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
| `init [--no-store] [--force]` | Generate a salt, set the password |
| `[OPTIONS] [--] CMD [ARGS...]` | Direct run; arguments after CMD pass through untouched |
| `run [OPTIONS] [--] CMD [ARGS...]` | Explicit run, sharing the direct entry's resolution and execution |
| `set NAME [VALUE] [--enc\|--plain] [--stdin] [-e FILE]... [-y]` | Write to every selected file after confirmation |
| `get NAME [OPTIONS]` | Print the final environment value, using the same resolution as run; missing names are errors |
| `list [-e FILE]...` &nbsp;(alias `ls`) | List key names and encryption status only |
| `rm NAME [-e FILE]... [-y]` | Remove every occurrence from the selected files after confirmation |
| `encrypt [-k GLOB]... [-e FILE]` &nbsp;(alias `enc`) | Bulk-encrypt one file according to its mode |
| `decrypt -k GLOB... [-e FILE]` &nbsp;(alias `dec`) | Decrypt one file to plaintext |
| `passwd [-e FILE]... [--no-store]` | Change the password and re-encrypt the selected files |
| `ui [--port N] [--strict-port]` | Local web UI |

All environment-file selectors use `-e`; omitted selectors use `.env`, except `passwd`, where omission changes only the credential config. `--config-file PATH` selects the credential config for every command, including `init` and `ui`, ahead of the existing default config location. Run and get still require initialization, including for plaintext input. Debug does not.

Run/get options:

- Repeat `-e FILE` to select files. Default precedence is **process environment > first file > later files**. With `-o` / `--override`, it is **last file > earlier files > process environment**. Within each file the last duplicate wins.
- Repeat `-v NAME=value` to inject temporary values after expansion. They have highest priority, repeated names use the last value, empty values are rejected, and values stay literal. `-v` has no effect on persistent edits.
- `-c [ENVIRONMENT]` selects `<base>.<environment>.local`, `<base>.local`, `<base>.<environment>`, then `<base>`, in that priority order for each `-e` base. Bare `-c` selects `<base>.local`, then `<base>`. Use `-c -- COMMAND` to disambiguate a bare cascade flag from its optional environment argument. Cascade and override conflict.
- Expansion is enabled over the merged environment, including decrypted values and inherited variables; `--no-expand` leaves references literal. Temporary `-v` values are applied afterward.
- `--debug` prints the candidate paths and temporary variable object, including their values, then exits without reading files, loading credentials, or executing a command.
- Run/get are quiet by default. `--quiet=false` / `-q=false` enables a summary on stderr; `--quiet` / `-q` silences it. Explicit flags take precedence over `LOCALENVX_QUIET=1|true|0|false`. Missing cascade candidates all together still produce a warning.

A missing default or explicitly selected file is an error. Missing cascade candidates are skipped; when all candidates are missing, a warning is printed and execution continues using the process environment plus `-v`. Other read errors remain errors.

Only winning ciphertext is decrypted. Values needed by expansion count as effective: if `REF=$SECRET` and `-v SECRET=temporary` is supplied, REF expands from SECRET's loaded value before the temporary replacement. Completely unused ciphertext shadowed by files, the process environment, or `-v` does not need a key.

Built-in command names take precedence: `localenvx get NAME` invokes get; `localenvx -- get NAME` runs an external executable named get. `-p` is unsupported. Use get instead.

Set/rm print target paths and affected key names before prompting `[Y/n]`. Enter confirms; `n` cancels; `-y` / `--yes` skips the prompt. Noninteractive input requires `-y`, also when stdin is reserved for a set value or password. Set updates the last occurrence and removes earlier duplicates; rm removes all occurrences. All changes are prepared and validated before saving. Each file is replaced atomically; a multi-file edit is not a filesystem transaction.

## Compatibility and migration

The compatibility baseline is [dotenv-cli 11.0.0](https://github.com/entropitor/dotenv-cli/blob/v11.0.0/cli.js), with [dotenv 17.1.0](https://github.com/motdotla/dotenv/blob/v17.1.0/lib/main.js) parsing and [dotenv-expand 12.0.0](https://github.com/motdotla/dotenv-expand/blob/v12.0.0/lib/main.js) expansion. Pinned oracle fixtures cover parsing and expansion using synthetic inputs; CLI tests use isolated `.env.example` fixtures. Localenvx retains encryption directives, initialization requirements, strict read errors, and its own opt-in summary.

Parsing supports whitespace around `=`, `KEY: value`, inline comments, multiline single/double/backtick quotes, and keys containing dots, hyphens or leading digits. Double quotes decode only `\n` and `\r`; other backslashes remain literal. Unchanged files render byte-for-byte. Edited files retain comments, order and quote style where representable; line endings are normalized to LF. An edit whose value cannot roundtrip through dotenv syntax fails before saving. Expansion supports references, defaults, alternate values, escaping and cyclic references. Pathological replacement cycles that hang upstream terminate with the repeated reference left literal.

Breaking interface changes:

```sh
# Before: later file wins by default
localenvx run .env.base .env.local -- npm dev
# After: first file wins by default
localenvx run -e .env.local -e .env.base -- npm dev
# Direct entry shares the same behavior
localenvx -e .env.local -e .env.base -- npm dev

# Before: get/set/rm and bulk operations used -f FILE
# After:
localenvx get API_URL -e config.vars
localenvx set API_URL https://example.com -e config.vars -y
localenvx rm API_URL -e config.vars -y
localenvx --config-file private/config.toml run -e config.vars -- npm dev
```

Old positional file arguments and `-f` / `--file` are removed. In direct/run forms, the first positional argument now names the executable. Get now reads the final expanded environment, including inherited variables and `-v`, rather than a raw file value.

## Password sources (highest precedence first)

1. `--password-stdin` / interactive input
2. `LOCALENVX_PASSWORD`
3. `password` in `~/.config/localenvx/config.toml` (the default; the file is forced to `0600`)
4. Interactive prompt; an error exit when stdin is not a TTY

`--password <value>` is deliberately **not** offered: it would land in shell history and `/proc/*/cmdline`.

## Moving to another machine

The key is `argon2id(password, salt)`. The salt is generated randomly at `init` time and stored **in plaintext** in the `[kdf]` section of `config.toml`. The salt is not a secret (leaking it is harmless; it only prevents rainbow tables and reuse across installs), but it is required for decryption:

```bash
# On the new machine: copy .env and config.toml, then
chmod 600 ~/.config/localenvx/config.toml
# If you do not want the password to travel, delete the password line from config.toml and use LOCALENVX_PASSWORD
```

**Do not** run `localenvx init` on the new machine — that generates a new salt, and even the same password will not open the old ciphertext.

## Encryption

```
encrypted:v1:<base64url( nonce[24] ‖ ciphertext ‖ tag[16] )>
```

XChaCha20-Poly1305, with the key derived from the password via argon2id (m=64MB, t=3, p=4). The **AAD binds the variable name**, so ciphertext pasted onto another key fails to decrypt. The stderr summary never prints values.

## Known trade-offs

The password is stored in plaintext in the config by default, so this **does not protect against active theft**. To tighten it, move the password out of the config and add these denies to your Claude Code settings:

```
Read(**/.env*)
Read(**/.config/localenvx/**)
Bash(localenvx get:*)
Bash(localenvx ui:*)
```
