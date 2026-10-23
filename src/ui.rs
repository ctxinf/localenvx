//! F7 — local web UI.
//!
//! A foreground process bound to 127.0.0.1 only, with no token and no timeout; Ctrl-C quits.
//! Security measures: check Origin / Sec-Fetch-Site, send no-store, mask values by default.

use anyhow::{Context, Result, bail};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tiny_http::{Header, Request, Response, Server};

use crate::crypto;
use crate::envfile::{EnvFile, Item};
use crate::session::Session;
use crate::term::{cyan, dim, green};

const PORT_SPAN: u16 = 100;

/// Inline favicon: a padlock over a `$`. One palette per color scheme, following the system theme.
const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <style>
    .bg { fill: #2f5ed8 }
    .fg { fill: none; stroke: #fff; stroke-width: 2.6; stroke-linecap: round; stroke-linejoin: round }
    @media (prefers-color-scheme: dark) { .bg { fill: #7aa2f7 } .fg { stroke: #16181d } }
  </style>
  <rect class="bg" width="32" height="32" rx="7"/>
  <rect class="fg" x="8" y="15" width="16" height="11" rx="2.5"/>
  <path class="fg" d="M11.5 15v-3.5a4.5 4.5 0 0 1 9 0V15"/>
</svg>
"##;

pub fn serve(start_port: u16, strict_port: bool, password_stdin: bool) -> Result<()> {
    let project = std::env::current_dir()?;
    // Verify the password up front, so we do not discover it is wrong only after opening the page.
    let mut sess = Session::open(password_stdin)?;
    sess.key()?;
    let sess = Mutex::new(sess);

    let (server, port) = bind(start_port, strict_port)?;
    let origin = format!("http://127.0.0.1:{port}");
    eprintln!(
        "{}  {}\n{}",
        green("localenvx ui"),
        cyan(&format!("http://127.0.0.1:{port}/")),
        dim(&format!(
            "  project {}   (Ctrl-C to quit)",
            project.display()
        ))
    );

    for req in server.incoming_requests() {
        if let Err(e) = handle(req, &sess, &project, &origin) {
            eprintln!("{} {e:#}", dim("ui:"));
        }
    }
    Ok(())
}

/// "Taken" means an actual bind failure; no pre-flight probing (avoids TOCTOU).
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
                    bail!("failed to bind 127.0.0.1:{port}: {e}");
                }
            }
        }
    }
    bail!("{start}..={last} are all taken")
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
        ("GET", "/favicon.svg") => respond(
            req,
            200,
            "image/svg+xml; charset=utf-8",
            FAVICON.as_bytes().to_vec(),
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

/// The only real remote risk is DNS rebinding / a malicious page hitting localhost, so cross-site requests are blocked outright.
fn check_origin(req: &Request, origin: &str) -> std::result::Result<(), String> {
    let get = |name: &str| {
        req.headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str().to_string())
    };
    if let Some(site) = get("Sec-Fetch-Site") {
        if site != "same-origin" && site != "none" {
            return Err(format!(
                "cross-site request rejected (Sec-Fetch-Site: {site})"
            ));
        }
    }
    if let Some(o) = get("Origin") {
        if o != origin {
            return Err(format!("cross-site request rejected (Origin: {o})"));
        }
    }
    // The Host must be a loopback address, which blocks DNS rebinding.
    if let Some(h) = get("Host") {
        let host = h.split(':').next().unwrap_or("");
        if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
            return Err(format!("non-loopback Host rejected: {h}"));
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
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self'",
        ),
    ] {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            resp.add_header(h);
        }
    }
    req.respond(resp).context("failed to send the response")
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
            &serde_json::json!({ "error": format!("request body is not valid JSON: {e}") }),
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

// ── File access: only .env* inside the project directory ────────────────────

fn safe_path(project: &Path, name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.contains('\\') || name.contains("..") || !name.starts_with(".env")
    {
        bail!("disallowed file name: {name}");
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
    // Return the lines verbatim (comments and blanks included) so the frontend can render
    // the .env the way it actually looks.
    let mut lines = Vec::new();
    for item in file.items() {
        lines.push(match item {
            Item::Blank => serde_json::json!({ "kind": "blank" }),
            Item::Comment(text) => serde_json::json!({ "kind": "comment", "text": text }),
            Item::Var(v) => {
                let value = if v.is_encrypted() {
                    crypto::decrypt(sess.key()?, &v.name, &v.value)?.to_string()
                } else {
                    v.value.clone()
                };
                serde_json::json!({
                    "kind": "var",
                    "name": v.name,
                    "value": value,
                    "encrypted": v.is_encrypted(),
                    "export": v.export,
                })
            }
        });
    }
    Ok(serde_json::json!({ "path": name, "mode": file.mode.as_str(), "lines": lines }))
}

fn write_var(sess: &Mutex<Session>, project: &Path, v: &serde_json::Value) -> Result<()> {
    let name = v["name"].as_str().context("missing name")?.to_string();
    let value = v["value"].as_str().context("missing value")?.to_string();
    let file_name = v["path"].as_str().context("missing path")?;
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
    let name = v["name"].as_str().context("missing name")?;
    let path = safe_path(project, v["path"].as_str().context("missing path")?)?;
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
