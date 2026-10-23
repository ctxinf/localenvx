#!/bin/sh
# Install a published localenvx binary; no sudo required.
set -eu
repo=ctxinf/localenvx
version=${LOCALENVX_VERSION:-latest}
bin_dir=${BIN_DIR:-"$HOME/.local/bin"}
case "$(uname -s)" in
  Linux) platform=unknown-linux-gnu ;;
  Darwin) platform=apple-darwin ;;
  *) echo 'Use the Windows release ZIP or cargo install on this platform.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo 'No prebuilt binary for this architecture; use cargo install localenvx.' >&2; exit 1 ;;
esac
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required command: $tool" >&2; exit 1; }
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum=shasum
else
  echo 'Required command: sha256sum or shasum' >&2; exit 1
fi
case "$version" in
  latest) base="https://github.com/$repo/releases/latest/download" ;;
  v[0-9]*) base="https://github.com/$repo/releases/download/$version" ;;
  *) echo 'LOCALENVX_VERSION must be latest or a v-prefixed release tag.' >&2; exit 1 ;;
esac
asset="localenvx-$arch-$platform.tar.gz"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
curl -fsSL "$base/$asset" -o "$work_dir/$asset"
curl -fsSL "$base/SHA256SUMS" -o "$work_dir/SHA256SUMS"
expected=$(awk -v name="$asset" '$2 == name {print $1}' "$work_dir/SHA256SUMS")
[ "${#expected}" = 64 ] || { echo 'Missing or invalid release checksum.' >&2; exit 1; }
if [ "$checksum" = sha256sum ]; then
  actual=$(sha256sum "$work_dir/$asset" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$work_dir/$asset" | cut -d ' ' -f 1)
fi
[ "$expected" = "$actual" ] || { echo 'Release checksum mismatch.' >&2; exit 1; }
tar -xzf "$work_dir/$asset" -C "$work_dir" ./localenvx
mkdir -p "$bin_dir"
install -m 755 "$work_dir/localenvx" "$bin_dir/localenvx"
printf 'Installed %s/localenvx\nAdd %s to PATH if needed.\n' "$bin_dir" "$bin_dir"
