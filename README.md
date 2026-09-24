# localenvx

本地开发用的加密环境变量管理工具。**磁盘上没有明文机密**，coding agent 无意中 `grep` / 读文件时拿不到值。

需求与威胁模型见 [design.md](./design.md)。

```bash
cargo build --release              # target/release/localenvx
scripts/install-local.sh           # 构建并装到 ~/.local/bin（BIN_DIR= 可改，--uninstall 卸载）
```

## 快速上手

```bash
localenvx init                                   # 生成 salt、设置密码（默认写入 config）
localenvx set OPENAI_API_KEY "sk-..." --enc      # 加密写入 .env
localenvx set PORT 3000                          # 明文
localenvx list                                   # 只看 key 名与加密状态
localenvx run .env.base .env.local -- npm dev    # 解密后 execve 子进程
localenvx ui                                     # http://127.0.0.1:27500/
```

## 文件格式

blacklist（**默认**，不写任何标记即是：全部加密，需 `@PLAIN` 豁免）：

```bash
# @PLAIN
LOG_LEVEL=debug
API_TOKEN=encrypted:v1:BHe9lUzNq4oS0tX...
```

whitelist（需显式声明：默认明文，需 `@ENC` 才加密）：

```bash
# @localenvx-mode:whitelist

NODE_ENV=development

# @ENC
DATABASE_URL=encrypted:v1:BFc4vRxLq8mN2pQ...
```

- 模式标记只在**第一个变量之前**生效；之后出现一律忽略，两种标记同时出现则报错。
- `@ENC` / `@PLAIN` 只作用于**紧邻的下一个变量**（中间不可有空行），同时出现则报错。
- 重写文件保留注释、空行、顺序、引号风格、`export ` 前缀、行内注释。

## 命令

| 命令 | 说明 |
|---|---|
| `init [--no-store] [--force]` | 生成 salt、设置密码 |
| `run [FILES...] [--override] -- CMD` | 分层加载（左→右优先级递增）后 `execve`；真实环境变量默认优先 |
| `set NAME [VALUE] [--enc\|--plain] [--stdin] [-f FILE]` | 写入变量 |
| `get NAME [-f FILE]` | 解密输出到 stdout |
| `list [FILES...]` &nbsp;（别名 `ls`） | 只列 key 名与加密状态 |
| `rm NAME [-f FILE]` | 删除变量（连带仅含指令的注释行） |
| `encrypt [-k GLOB]... [-f FILE]` &nbsp;（别名 `enc`） | 批量加密明文；缺省为「该文件模式下应加密的全部变量」 |
| `decrypt -k GLOB... [-f FILE]` &nbsp;（别名 `dec`） | 解密为明文（明文落盘，慎用） |
| `passwd [FILES...] [--no-store]` | 换密码并重加密指定文件 |
| `ui [--port N] [--strict-port]` | 本地 Web UI |

全局开关：`--password-stdin`（从 stdin 读密码）、`--quiet` / `LOCALENVX_QUIET=1`（静音 stderr 摘要）。

## 密码来源（优先级从高到低）

1. `--password-stdin` / 交互输入
2. `LOCALENVX_PASSWORD`
3. `~/.config/localenvx/config.toml` 的 `password`（默认方式，文件强制 `0600`）
4. 交互提示；非 TTY 则报错退出

刻意**不提供** `--password <值>`：避免进 shell history 与 `/proc/*/cmdline`。

## 换机器

密钥 = `argon2id(密码, salt)`，salt 在 `init` 时随机生成、**明文**存在 `config.toml` 的 `[kdf]` 段。
salt 不是秘密（泄露无害，作用只是防彩虹表与跨安装复用），但它是解密的必要参数：

```bash
# 新机器上：拷 .env 与 config.toml，然后
chmod 600 ~/.config/localenvx/config.toml
# 不想让密码跟着走，就删掉 config.toml 里的 password 行，改用 LOCALENVX_PASSWORD
```

**不要**在新机器上跑 `localenvx init` —— 那会生成新 salt，同样的密码也解不开旧密文。

## 加密

```
encrypted:v1:<base64url( nonce[24] ‖ ciphertext ‖ tag[16] )>
```

XChaCha20-Poly1305，密钥由 argon2id（m=64MB, t=3, p=4）从密码派生；**AAD 绑定变量名**，
密文剪贴到别的 key 上会解密失败。stderr 摘要绝不打印 value。

## 已知取舍

密码默认明文存在 config 里，因此**不防主动窃取**（design.md §1.2 T2）。要收紧就把密码移出 config，
并在 Claude Code settings 里 deny：

```
Read(**/.env*)
Read(**/.config/localenvx/**)
Bash(localenvx get:*)
Bash(localenvx ui:*)
```
