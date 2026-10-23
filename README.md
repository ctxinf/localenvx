# localenvx

dotenv-cli-like usage. dotenvx-style encryption. A local encrypted .env manager.

## Usage

```bash
# Load .env, decrypt its values, and run your command.
localenvx -- node app.js
# Do the same with the explicit run command.
localenvx run -- node app.js
# Load multiple files (.env.local takes priority over .env).
localenvx -e .env.local -e .env -- node app.js
# Load a specific environment file.
localenvx -e .env.test -- node app.js
# Let .env values override existing process environment variables.
localenvx -o -- node app.js
# Load development files, starting with .env.development.local.
localenvx -c development -- node app.js
# Load .env.local before .env when available.
localenvx -c -- node app.js
# Set a temporary value for this command only.
localenvx -v PORT=4000 -- node app.js
# Keep variable references such as $HOST literal.
localenvx --no-expand -- node app.js
# Preview file selection without loading files or running the command.
localenvx --debug -- node app.js
```

For first-time setup, run `init` before running your app:

```bash
# Create local credentials (the password is stored locally by default).
localenvx init
# Check credentials and .env status without revealing values.
localenvx status
# Save an encrypted secret in .env.
localenvx set API_TOKEN example-secret --enc -y
# Save a readable value in .env.
localenvx set PORT 3000 --plain -y
```

### How the .env looks like

```dotenv
# Secret values are stored as ciphertext (shortened here).
API_TOKEN=encrypted:v1:BHe9lUzNq4oS0tX...

# Use @PLAIN to keep the immediately following value readable.
# @PLAIN
PORT=3000
```

### How encryption and decryption work

`set --enc` turns your secret into ciphertext before saving it to `.env`.
When you run a command, localenvx uses your local credentials to decrypt the value
and passes it to your app as a normal environment variable. Your app sees the
original secret; `.env` stays encrypted. Everything happens on your machine.

## Install

### Installer (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/ctxinf/localenvx/main/scripts/install.sh | sh
```

### Homebrew

```bash
brew tap ctxinf/localenvx https://github.com/ctxinf/localenvx
brew install ctxinf/localenvx/localenvx
```

### Cargo

```bash
cargo install localenvx --locked
```

### Prebuilt binary (Linux/macOS/Windows)

Download from [GitHub Releases](https://github.com/ctxinf/localenvx/releases) for Linux, macOS, or Windows (x64/ARM64).

## More

Run `localenvx skill` or read [SKILL.md](SKILL.md) for the complete guide.
