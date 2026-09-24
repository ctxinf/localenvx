#!/usr/bin/env bash
# 本机安装 localenvx：cargo build --release 后把单二进制装到 BIN_DIR。
#
#   scripts/install-local.sh                 # 装到 ~/.local/bin
#   BIN_DIR=/usr/local/bin scripts/install-local.sh
#   scripts/install-local.sh --uninstall
#   scripts/install-local.sh --debug         # 用 debug 构建（更快，仅调试用）

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
    *)           echo "未知参数: $arg（用 --help 看用法）" >&2; exit 2 ;;
  esac
done

target="$BIN_DIR/localenvx"

if [ "$uninstall" = 1 ]; then
  if [ -e "$target" ]; then
    rm -f -- "$target"
    echo "✓ 已删除 $target"
  else
    echo "· $target 不存在，无事可做"
  fi
  echo "· 配置与密码仍在 ${XDG_CONFIG_HOME:-$HOME/.config}/localenvx/（如需一并删除请手动确认后再删）"
  exit 0
fi

command -v cargo >/dev/null || { echo "找不到 cargo，请先装 Rust 工具链" >&2; exit 1; }

echo "· 构建 ($profile) …"
if [ "$profile" = release ]; then
  cargo build --release --manifest-path "$repo_root/Cargo.toml"
else
  cargo build --manifest-path "$repo_root/Cargo.toml"
fi

built="$repo_root/target/$profile/localenvx"
[ -x "$built" ] || { echo "构建产物不存在: $built" >&2; exit 1; }

mkdir -p -- "$BIN_DIR"
# 先装到临时名再 rename：正在运行的旧进程不受影响，且替换是原子的。
tmp="$BIN_DIR/.localenvx.new.$$"
install -m 0755 -- "$built" "$tmp"
mv -f -- "$tmp" "$target"

echo "✓ 已安装 $target"
"$target" --version

case ":${PATH}:" in
  *":$BIN_DIR:"*) ;;
  *) echo "⚠️  $BIN_DIR 不在 PATH 里，加一行到 ~/.zshrc：
      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

if [ ! -e "${LOCALENVX_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/localenvx}/config.toml" ]; then
  echo "· 还没初始化，下一步：localenvx init"
fi
