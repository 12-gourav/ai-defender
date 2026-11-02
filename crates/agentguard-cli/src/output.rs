//! Output helpers: everything the CLI prints to stdout goes through here so that agent-
//! originated strings are sanitised in one place (Phase 0 review, G12).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::fmt::Write as _;

use serde::Serialize;

/// Replace control characters, ANSI escapes and Unicode direction/zero-width code points with
/// visible escapes so text cannot rewrite the terminal or disguise itself.
#[must_use]
pub fn sanitise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            // Bidirectional overrides and isolates, zero-width and joiner characters.
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}' => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Print a line to stdout after sanitising.
pub fn line(text: &str) {
    println!("{}", sanitise(text));
}

/// Print a serialisable value as pretty JSON. Serialisation failure is reported on stderr and
/// does not panic.
pub fn json<T: Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("error: cannot render JSON output: {e}"),
    }
}

/// A two-column table rendered with aligned columns.
#[derive(Debug, Default)]
pub struct Table {
    rows: Vec<(String, String)>,
}

impl Table {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row.
    pub fn row(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.rows.push((key.into(), value.into()));
        self
    }

    /// Render to a string (sanitised).
    #[must_use]
    pub fn render(&self) -> String {
        let width = self
            .rows
            .iter()
            .map(|(k, _)| k.chars().count())
            .max()
            .unwrap_or(0);
        let mut out = String::new();
        for (k, v) in &self.rows {
            let _ = writeln!(
                out,
                "{:<width$}  {}",
                sanitise(k),
                sanitise(v),
                width = width
            );
        }
        out
    }

    /// Print the table.
    pub fn print(&self) {
        print!("{}", self.render());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_escapes_ansi_bidi_and_zero_width() {
        assert_eq!(sanitise("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(sanitise("x\u{202E}y"), "x\\u{202e}y");
        assert_eq!(sanitise("x\u{200B}y"), "x\\u{200b}y");
        assert_eq!(sanitise("plain\ttab\nnl"), "plain\ttab\nnl");
        assert_eq!(sanitise("héllo"), "héllo");
    }

    #[test]
    fn table_aligns() {
        let mut t = Table::new();
        t.row("a", "1").row("longer", "2");
        let r = t.render();
        assert_eq!(r, "a       1\nlonger  2\n");
    }
}
