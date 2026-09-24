#!/usr/bin/env bash
# Install localenvx locally: run cargo build --release, then put the single binary in BIN_DIR.
#
#   scripts/install-local.sh                 # install into ~/.local/bin
#   BIN_DIR=/usr/local/bin scripts/install-local.sh
#   scripts/install-local.sh --uninstall
#   scripts/install-local.sh --debug         # use the debug build (faster, debugging only)

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR=${BIN_DIR:-"$HOME/.local/bin"}
profile=release
uninstall=0

for arg in "$@"; do
  case $arg in
    --uninstall) uninstall=1 ;;
    --debug)     profile=debug ;;
    -h|--help)   sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           echo "unknown argument: $arg (run --help for usage)" >&2; exit 2 ;;
  esac
done

target="$BIN_DIR/localenvx"

if [ "$uninstall" = 1 ]; then
  if [ -e "$target" ]; then
    rm -f -- "$target"
    echo "✓ removed $target"
  else
    echo "· $target does not exist, nothing to do"
  fi
  echo "· config and password remain in ${XDG_CONFIG_HOME:-$HOME/.config}/localenvx/ (remove them manually if you want them gone)"
  exit 0
fi

command -v cargo >/dev/null || { echo "cargo not found; install the Rust toolchain first" >&2; exit 1; }

echo "· building ($profile) …"
if [ "$profile" = release ]; then
  cargo build --release --manifest-path "$repo_root/Cargo.toml"
else
  cargo build --manifest-path "$repo_root/Cargo.toml"
fi

built="$repo_root/target/$profile/localenvx"
[ -x "$built" ] || { echo "build artifact missing: $built" >&2; exit 1; }

mkdir -p -- "$BIN_DIR"
# Install under a temporary name, then rename: running processes are unaffected and the swap is atomic.
tmp="$BIN_DIR/.localenvx.new.$$"
install -m 0755 -- "$built" "$tmp"
mv -f -- "$tmp" "$target"

echo "✓ installed $target"
"$target" --version

case ":${PATH}:" in
  *":$BIN_DIR:"*) ;;
  *) echo "⚠️  $BIN_DIR is not on PATH; add this line to ~/.zshrc:
      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

if [ ! -e "${LOCALENVX_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/localenvx}/config.toml" ]; then
  echo "· not initialized yet; next step: localenvx init"
fi
