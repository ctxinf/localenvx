//! Inspect logging on stderr: never prints values, only key names.

use std::io::IsTerminal;
use std::sync::OnceLock;

pub fn quiet() -> bool {
    static Q: OnceLock<bool> = OnceLock::new();
    if let Some(quiet) = FORCE_QUIET.with(|c| c.get()) {
        return quiet;
    }
    *Q.get_or_init(|| {
        matches!(
            std::env::var("LOCALENVX_QUIET").as_deref(),
            Ok("1") | Ok("true")
        )
    })
}

thread_local! {
    static FORCE_QUIET: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

pub fn set_quiet(on: bool) {
    FORCE_QUIET.with(|c| c.set(Some(on)));
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

fn confirmation_answer(answer: &str) -> Option<bool> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

pub fn confirm(prompt: &str, yes: bool) -> anyhow::Result<bool> {
    use std::io::Write;
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("confirmation requires a terminal; pass -y to proceed noninteractively");
    }
    loop {
        eprint!("{prompt} [Y/n] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer)? == 0 {
            anyhow::bail!("confirmation input ended without an answer");
        }
        if let Some(answer) = confirmation_answer(&answer) {
            return Ok(answer);
        }
        eprintln!("Please answer yes or no.");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn enter_means_yes_but_invalid_answers_do_not() {
        assert_eq!(super::confirmation_answer("\n"), Some(true));
        assert_eq!(super::confirmation_answer("YES"), Some(true));
        assert_eq!(super::confirmation_answer("n"), Some(false));
        assert_eq!(super::confirmation_answer("anything"), None);
    }
}
