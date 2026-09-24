# localenvx

Encrypted environment-variable manager for local development. **No plaintext secrets on disk**, so a coding agent that happens to `grep` or read files gets nothing.

Requirements and threat model live in [design.md](./design.md).

```bash
cargo build --release              # target/release/localenvx
scripts/install-local.sh           # build and install into ~/.local/bin (BIN_DIR= to change, --uninstall to remove)
```

## Quick start

```bash
localenvx init                                   # generate a salt, set the password (stored in the config by default)
localenvx set OPENAI_API_KEY "sk-..." --enc      # write encrypted into .env
localenvx set PORT 3000                          # plaintext
localenvx list                                   # key names and encryption status only
localenvx run .env.base .env.local -- npm dev    # decrypt, then execve the child process
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
| `run [FILES...] [--override] -- CMD` | Layered load (precedence increasing left→right), then `execve`; the real environment wins by default |
| `set NAME [VALUE] [--enc\|--plain] [--stdin] [-f FILE]` | Write a variable |
| `get NAME [-f FILE]` | Decrypt to stdout |
| `list [FILES...]` &nbsp;(alias `ls`) | List key names and encryption status only |
| `rm NAME [-f FILE]` | Remove a variable (along with a directive-only comment line) |
| `encrypt [-k GLOB]... [-f FILE]` &nbsp;(alias `enc`) | Bulk-encrypt plaintext; defaults to "every variable this file's mode says should be encrypted" |
| `decrypt -k GLOB... [-f FILE]` &nbsp;(alias `dec`) | Decrypt to plaintext (lands on disk — use with care) |
| `passwd [FILES...] [--no-store]` | Change the password and re-encrypt the given files |
| `ui [--port N] [--strict-port]` | Local web UI |

Global flags: `--password-stdin` (read the password from stdin), `--quiet` / `LOCALENVX_QUIET=1` (silence the stderr summary).

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

The password is stored in plaintext in the config by default, so this **does not protect against active theft** (design.md §1.2 T2). To tighten it, move the password out of the config and add these denies to your Claude Code settings:

```
Read(**/.env*)
Read(**/.config/localenvx/**)
Bash(localenvx get:*)
Bash(localenvx ui:*)
```
