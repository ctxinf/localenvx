# Changelog

## [0.6.0] - 2026-10-23

### Added

- `localenvx manage init --project` creates `.localenvx/config.toml` in the current directory. It conflicts with `--config-file` and preserves the existing safeguards against replacing credentials or stranding encrypted values.
- `localenvx manage ls --all` discovers `.env` and `.env.*` files in the current directory, sorted by filename, excluding temporary `.tmp` files and directories.
- `manage get` reports effective and ineffective file sources on stderr while keeping the resolved value on stdout. `--quiet` suppresses source diagnostics.

### Changed

- Simplified `manage ls` to accept repeated `-e FILE` selectors or `--all`; listing metadata does not require credentials.
- Improved `manage status` with colors, icons, clearer credential and file metadata, and more compact output.
- The local web UI now supports inline addition and editing, multiline value editors, encryption-mode selection, and cancellation with Escape.
- Improved web UI file-comment placement, horizontal table scrolling, value layout, and save/load feedback.
- Expanded setup, usage, credential-backup, and recovery documentation.

### Fixed

- Resolved a Clippy warning in CLI source-reporting tests so release checks pass with current Rust toolchains.

### Release packaging

- Include this changelog in Cargo packages and prebuilt archives, and use its version entry for GitHub release notes.

## [0.5.0] - 2026-10-23

### Breaking changes

- Reorganized the CLI into runtime commands (`localenvx -- COMMAND` or `localenvx run -- COMMAND`) and management commands under `localenvx manage`. Options are scoped to each command.
- Replaced password-based credentials with version 2 credential files containing a randomly generated 256-bit encryption key. Password prompts, password environment variables, `passwd`, `--password-stdin`, `--no-store`, and `--force` were removed.
- Initialization never overwrites an existing credential file. Version 1 password-based credential files are rejected without modifying files.

### Migration from 0.4.x

1. Use 0.4.2 with the original credentials to decrypt existing environment files.
2. Back up and move aside the old credential file.
3. Run `localenvx manage init` with the new version, then encrypt the environment files using the new key.
4. Back up the new credential file securely and keep it separate from encrypted environment files. A replacement key cannot recover values encrypted with a lost key.

### Changed

- Updated the local web UI, bundled usage guide, installer guidance, and cross-platform CLI tests for the new command and credential model.
- Removed password-terminal test dependencies and fixed Windows terminal-adapter installation YAML.

[0.6.0]: https://github.com/ctxinf/localenvx/compare/936ca86673b35bd894fded0974a403e0bafabd25...v0.6.0
[0.5.0]: https://github.com/ctxinf/localenvx/compare/v0.4.2...936ca86673b35bd894fded0974a403e0bafabd25
