# localenvx

The dotenv-cli workflow with dotenvx-style value encryption, kept entirely local.
Load `.env` files, encrypt individual values, and decrypt them into a child process environment.

```bash
# Create local credentials (password stored locally by default).
localenvx init
# Store an encrypted value in .env.
localenvx set API_TOKEN example-secret --enc -y
# Keep non-secret values readable.
localenvx set PORT 3000 --plain -y
# Load files, decrypt values, and start your app.
localenvx -e .env.local -e .env -- node app.js
# Print the complete guide for people and agents.
localenvx skill
```

Install a prebuilt binary from [GitHub Releases](https://github.com/ctxinf/localenvx/releases) for Linux, macOS, or Windows (x64 and ARM64), or use the installer on Linux/macOS:

```bash
# Download, verify the release checksum, and install into ~/.local/bin.
curl -fsSL https://raw.githubusercontent.com/ctxinf/localenvx/main/scripts/install.sh | sh
# Build from source with Homebrew (requires the version tag).
brew tap ctxinf/localenvx https://github.com/ctxinf/localenvx
brew install ctxinf/localenvx/localenvx
# Build from crates.io with Cargo (also available for other Rust targets).
cargo install localenvx --locked
```

See [SKILL.md](SKILL.md) for configuration, precedence, encryption, and credential storage details.
