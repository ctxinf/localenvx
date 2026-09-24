//! Inspect logging on stderr: never prints values, only key names.

use std::io::IsTerminal;
use std::sync::OnceLock;

pub fn quiet() -> bool {
    static Q: OnceLock<bool> = OnceLock::new();
    *Q.get_or_init(|| {
        matches!(
            std::env::var("LOCALENVX_QUIET").as_deref(),
            Ok("1") | Ok("true")
        )
    }) || FORCE_QUIET.with(|c| c.get())
}

thread_local! {
    static FORCE_QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn set_quiet(on: bool) {
    FORCE_QUIET.with(|c| c.set(on));
}

pub fn color() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal())
}

pub fn paint(code: &str, s: &str) -> String {
    if color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn dim(s: &str) -> String {
    paint("2", s)
}
pub fn green(s: &str) -> String {
    paint("32", s)
}
pub fn yellow(s: &str) -> String {
    paint("33", s)
}
pub fn cyan(s: &str) -> String {
    paint("36", s)
}

macro_rules! note {
    ($($arg:tt)*) => {
        if !$crate::term::quiet() { eprintln!($($arg)*); }
    };
}
pub(crate) use note;
