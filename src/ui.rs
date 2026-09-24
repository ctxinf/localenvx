//! F7 — 本地 Web UI。
//!
//! 前台进程、只绑 127.0.0.1、无 token、无超时，Ctrl-C 即退出。
//! 安全要点见 design.md §F7：校验 Origin / Sec-Fetch-Site、no-store、value 默认打码。

use anyhow::{Context, Result, bail};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tiny_http::{Header, Request, Response, Server};

use crate::crypto;
use crate::envfile::EnvFile;
use crate::session::Session;
use crate::term::{cyan, dim, green};

const PORT_SPAN: u16 = 100;

pub fn serve(start_port: u16, strict_port: bool, password_stdin: bool) -> Result<()> {
    let project = std::env::current_dir()?;
    // 先验一次密码，免得开了页面才发现解不开。
    let mut sess = Session::open(password_stdin)?;
    sess.key()?;
    let sess = Mutex::new(sess);

    let (server, port) = bind(start_port, strict_port)?;
    let origin = format!("http://127.0.0.1:{port}");
    eprintln!(
        "{}  {}\n{}",
        green("localenvx ui"),
        cyan(&format!("http://127.0.0.1:{port}/")),
        dim(&format!("  项目 {}   (Ctrl-C 结束)", project.display()))
    );

    for req in server.incoming_requests() {
        if let Err(e) = handle(req, &sess, &project, &origin) {
            eprintln!("{} {e:#}", dim("ui:"));
        }
    }
    Ok(())
}

/// 「被占用」以实际 bind 失败为准，不做预检探测（避免 TOCTOU）。
fn bind(start: u16, strict: bool) -> Result<(Server, u16)> {
    let last = if strict {
        start
    } else {
        start.saturating_add(PORT_SPAN - 1)
    };
    for port in start..=last {
        match Server::http(("127.0.0.1", port)) {
            Ok(s) => return Ok((s, port)),
            Err(e) => {
                let io_kind = e.downcast_ref::<std::io::Error>().map(|io| io.kind());
                if strict || io_kind != Some(std::io::ErrorKind::AddrInUse) {
                    bail!("绑定 127.0.0.1:{port} 失败: {e}");
                }
            }
        }
    }
    bail!("{start}..={last} 全部被占用")
}

fn handle(req: Request, sess: &Mutex<Session>, project: &Path, origin: &str) -> Result<()> {
    if let Err(msg) = check_origin(&req, origin) {
        return respond(req, 403, "text/plain; charset=utf-8", msg.into_bytes());
    }
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));

    match (req.method().as_str(), path) {
        ("GET", "/") => respond(
            req,
            200,
            "text/html; charset=utf-8",
            page(project).into_bytes(),
        ),
        ("GET", "/api/files") => {
            let files = list_env_files(project);
            json(
                req,
                200,
                &serde_json::json!({ "project": project.display().to_string(), "files": files }),
            )
        }
        ("GET", "/api/file") => {
            let name = param(query, "path").unwrap_or_else(|| ".env".into());
            match read_file(sess, project, &name) {
                Ok(v) => json(req, 200, &v),
                Err(e) => json(req, 400, &serde_json::json!({ "error": format!("{e:#}") })),
            }
        }
        ("POST", "/api/set") => body_json(req, |req, v| match write_var(sess, project, &v) {
            Ok(()) => json(req, 200, &serde_json::json!({ "ok": true })),
            Err(e) => json(req, 400, &serde_json::json!({ "error": format!("{e:#}") })),
        }),
        ("POST", "/api/rm") => body_json(req, |req, v| match remove_var(project, &v) {
            Ok(()) => json(req, 200, &serde_json::json!({ "ok": true })),
            Err(e) => json(req, 400, &serde_json::json!({ "error": format!("{e:#}") })),
        }),
        _ => respond(req, 404, "text/plain; charset=utf-8", b"not found".to_vec()),
    }
}

/// 唯一真实的远程风险是 DNS rebinding / 恶意网页打 localhost，这里直接挡掉跨站请求。
fn check_origin(req: &Request, origin: &str) -> std::result::Result<(), String> {
    let get = |name: &str| {
        req.headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str().to_string())
    };
    if let Some(site) = get("Sec-Fetch-Site") {
        if site != "same-origin" && site != "none" {
            return Err(format!("拒绝跨站请求 (Sec-Fetch-Site: {site})"));
        }
    }
    if let Some(o) = get("Origin") {
        if o != origin {
            return Err(format!("拒绝跨站请求 (Origin: {o})"));
        }
    }
    // Host 必须是回环地址，挡住 DNS rebinding。
    if let Some(h) = get("Host") {
        let host = h.split(':').next().unwrap_or("");
        if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
            return Err(format!("拒绝非回环 Host: {h}"));
        }
    }
    Ok(())
}

fn respond(req: Request, status: u16, ctype: &str, body: Vec<u8>) -> Result<()> {
    let len = body.len();
    let mut resp = Response::new(status.into(), vec![], Cursor::new(body), Some(len), None);
    for (k, v) in [
        ("Content-Type", ctype),
        ("Cache-Control", "no-store"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        ),
    ] {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            resp.add_header(h);
        }
    }
    req.respond(resp).context("发送响应失败")
}

fn json(req: Request, status: u16, v: &serde_json::Value) -> Result<()> {
    respond(
        req,
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(v)?,
    )
}

fn body_json<F>(mut req: Request, f: F) -> Result<()>
where
    F: FnOnce(Request, serde_json::Value) -> Result<()>,
{
    let mut buf = String::new();
    req.as_reader().read_to_string(&mut buf)?;
    match serde_json::from_str(&buf) {
        Ok(v) => f(req, v),
        Err(e) => json(
            req,
            400,
            &serde_json::json!({ "error": format!("请求体不是合法 JSON: {e}") }),
        ),
    }
}

fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(x) => {
                    out.push(x);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── 文件访问：只允许项目目录下的 .env* ────────────────────────────────────────

fn safe_path(project: &Path, name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.contains('\\') || name.contains("..") || !name.starts_with(".env")
    {
        bail!("不允许的文件名: {name}");
    }
    Ok(project.join(name))
}

fn list_env_files(project: &Path) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(project)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(".env") && !n.ends_with(".tmp"))
        .collect();
    files.sort();
    files
}

fn read_file(sess: &Mutex<Session>, project: &Path, name: &str) -> Result<serde_json::Value> {
    let path = safe_path(project, name)?;
    let file = if path.exists() {
        EnvFile::load(&path)?
    } else {
        EnvFile::empty_at(&path)
    };
    let mut sess = sess.lock().unwrap();
    let mut vars = Vec::new();
    for v in file.vars() {
        let value = if v.is_encrypted() {
            crypto::decrypt(sess.key()?, &v.name, &v.value)?.to_string()
        } else {
            v.value.clone()
        };
        vars.push(serde_json::json!({
            "name": v.name,
            "value": value,
            "encrypted": v.is_encrypted(),
        }));
    }
    Ok(serde_json::json!({ "path": name, "mode": file.mode.as_str(), "vars": vars }))
}

fn write_var(sess: &Mutex<Session>, project: &Path, v: &serde_json::Value) -> Result<()> {
    let name = v["name"].as_str().context("缺少 name")?.to_string();
    let value = v["value"].as_str().context("缺少 value")?.to_string();
    let file_name = v["path"].as_str().context("缺少 path")?;
    let want_enc = match v["enc"].as_str().unwrap_or("auto") {
        "enc" => Some(true),
        "plain" => Some(false),
        _ => None,
    };
    let path = safe_path(project, file_name)?;
    let mut file = if path.exists() {
        EnvFile::load(&path)?
    } else {
        EnvFile::empty_at(&path)
    };
    file.upsert(&name, "", want_enc)?;
    let encrypt = want_enc.unwrap_or_else(|| file.should_encrypt(&name));
    let stored = if encrypt {
        let mut sess = sess.lock().unwrap();
        crypto::encrypt(sess.key()?, &name, &value)?
    } else {
        value
    };
    file.set_value(&name, &stored)?;
    file.save()
}

fn remove_var(project: &Path, v: &serde_json::Value) -> Result<()> {
    let name = v["name"].as_str().context("缺少 name")?;
    let path = safe_path(project, v["path"].as_str().context("缺少 path")?)?;
    let mut file = EnvFile::load(&path)?;
    file.remove(name)?;
    file.save()
}

fn page(project: &Path) -> String {
    let title = html_escape(&project.display().to_string());
    include_str!("ui.html").replace("{{PROJECT}}", &title)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_escape() {
        let p = Path::new("/tmp/proj");
        assert!(safe_path(p, "../../etc/passwd").is_err());
        assert!(safe_path(p, "secrets.txt").is_err());
        assert!(safe_path(p, ".env.local").is_ok());
    }

    #[test]
    fn decodes_query() {
        assert_eq!(
            param("path=.env.local", "path").as_deref(),
            Some(".env.local")
        );
        assert_eq!(param("path=a%2Eb", "path").as_deref(), Some("a.b"));
    }
}
