//! Shell mode: a strict parser for the subset of POSIX shell syntax AgentGuard can classify
//! exactly, and a canonical rendering of what it parsed.
//!
//! Supported: simple commands of literal words (bare, single-quoted, or double-quoted without
//! `$`, backquotes or escapes other than `\"` and `\\`), joined by `;`, newline, `&&`, `||` and
//! `|`, with redirections `>`, `>>`, `<`, `2>`, `2>>` and `2>&1` to literal targets.
//!
//! Refused, never executed: command substitution, parameter and arithmetic expansion,
//! globbing, brace and tilde expansion, background jobs, subshells and groups, here-documents,
//! process substitution, comments, history expansion, variable assignments, reserved words
//! (`if`, `for`, functions, ...), and builtins that change how later words are interpreted
//! (`eval`, `exec`, `source`, `.`, `alias`, `cd`, `export`, `set`, `trap`, ...).
//!
//! The executor runs the canonical rendering, not the submitted text: every word is re-quoted
//! with [`agentguard_engine::normalize::quote_argv`], so the shell interprets exactly the
//! structure that was parsed and evaluated. This is a classifier for a subset, not a shell
//! implementation; anything outside the subset is refused rather than guessed.

use agentguard_engine::normalize::quote_argv;

/// Most simple commands in one script.
pub const MAX_COMMANDS: usize = 16;

/// Why a script is outside the supported subset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported shell syntax: {0}")]
pub struct Unsupported(pub &'static str);

/// How two commands are joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joiner {
    /// `;` or newline.
    Sequence,
    /// `&&`.
    And,
    /// `||`.
    Or,
    /// `|`.
    Pipe,
}

impl Joiner {
    const fn as_str(self) -> &'static str {
        match self {
            Joiner::Sequence => ";",
            Joiner::And => "&&",
            Joiner::Or => "||",
            Joiner::Pipe => "|",
        }
    }
}

/// A redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    /// `> target` (truncate).
    Out(String),
    /// `>> target`.
    Append(String),
    /// `< source`.
    In(String),
    /// `2> target`.
    ErrOut(String),
    /// `2>> target`.
    ErrAppend(String),
    /// `2>&1`.
    ErrToOut,
}

/// One simple command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// Words; the first is the program.
    pub argv: Vec<String>,
    /// Redirections, in order.
    pub redirects: Vec<Redirect>,
}

/// A parsed script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// Commands in order.
    pub commands: Vec<SimpleCommand>,
    /// `joiners[i]` joins `commands[i]` and `commands[i + 1]`.
    pub joiners: Vec<Joiner>,
}

const RESERVED: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "select", "time", "coproc", "!", "{", "}", "[[", "]]",
];

const REFUSED_BUILTINS: &[&str] = &[
    "eval", "exec", "source", ".", "alias", "unalias", "cd", "pushd", "popd", "export", "unset",
    "set", "shopt", "trap", "builtin", "command", "enable", "hash", "readonly", "declare",
    "typeset", "local", "let", "ulimit", "umask", "exit", "return", "fc", "history",
];

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Join(Joiner),
    Redir(&'static str),
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '_' | '-' | '.' | '/' | ':' | '=' | ',' | '+' | '@' | '%' | '^'
        )
}

// A tokenizer for a deliberately small grammar; splitting it would obscure the rules.
#[allow(clippy::too_many_lines)]
fn tokenize(script: &str) -> Result<Vec<Token>, Unsupported> {
    let mut tokens = Vec::new();
    let mut chars = script.chars().peekable();
    let mut word: Option<String> = None;
    let end_word = |word: &mut Option<String>, tokens: &mut Vec<Token>| {
        if let Some(w) = word.take() {
            tokens.push(Token::Word(w));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => end_word(&mut word, &mut tokens),
            '\n' | ';' => {
                end_word(&mut word, &mut tokens);
                if chars.peek() == Some(&';') {
                    return Err(Unsupported("`;;` case terminators"));
                }
                tokens.push(Token::Join(Joiner::Sequence));
            }
            '&' => {
                end_word(&mut word, &mut tokens);
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(Token::Join(Joiner::And));
                } else {
                    return Err(Unsupported("background jobs (`&`)"));
                }
            }
            '|' => {
                end_word(&mut word, &mut tokens);
                match chars.peek() {
                    Some('|') => {
                        chars.next();
                        tokens.push(Token::Join(Joiner::Or));
                    }
                    Some('&') => return Err(Unsupported("`|&` pipelines")),
                    _ => tokens.push(Token::Join(Joiner::Pipe)),
                }
            }
            '>' | '<' => {
                // `2>`, `2>>` and `2>&1` arrive with the `2` already in `word`.
                let fd2 = word.as_deref() == Some("2");
                if fd2 {
                    word = None;
                } else {
                    end_word(&mut word, &mut tokens);
                }
                let op: &'static str = match (c, chars.peek().copied(), fd2) {
                    ('>', Some('>'), false) => {
                        chars.next();
                        ">>"
                    }
                    ('>', Some('>'), true) => {
                        chars.next();
                        "2>>"
                    }
                    ('>', Some('&'), true) => {
                        chars.next();
                        if chars.next() != Some('1') {
                            return Err(Unsupported(
                                "file descriptor duplication other than `2>&1`",
                            ));
                        }
                        "2>&1"
                    }
                    ('>', Some('&' | '|' | '('), _) => {
                        return Err(Unsupported("`>&`, `>|` or process substitution"))
                    }
                    ('>', _, false) => ">",
                    ('>', _, true) => "2>",
                    ('<', Some('<' | '>' | '&' | '('), _) => {
                        return Err(Unsupported(
                            "here-documents, `<>`, `<&` or process substitution",
                        ))
                    }
                    ('<', _, false) => "<",
                    _ => return Err(Unsupported("redirecting standard error as input")),
                };
                tokens.push(Token::Redir(op));
            }
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => w.push(ch),
                        None => return Err(Unsupported("an unterminated single quote")),
                    }
                }
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('$' | '`') => {
                            return Err(Unsupported(
                                "expansion or substitution inside double quotes",
                            ))
                        }
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => w.push(e),
                            _ => return Err(Unsupported(
                                "backslash escapes inside double quotes other than \\\" and \\\\",
                            )),
                        },
                        Some(ch) => w.push(ch),
                        None => return Err(Unsupported("an unterminated double quote")),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(e) if e != '\n' => word.get_or_insert_with(String::new).push(e),
                _ => return Err(Unsupported("line continuations")),
            },
            '$' => {
                return Err(Unsupported(
                    "parameter, arithmetic or command expansion (`$`)",
                ))
            }
            '`' => return Err(Unsupported("command substitution (backquotes)")),
            '(' | ')' => return Err(Unsupported("subshells or grouping")),
            '*' | '?' | '[' | ']' => return Err(Unsupported("globbing (unquoted `*`, `?`, `[`)")),
            '{' | '}' => return Err(Unsupported("brace expansion or command groups")),
            '~' if word.is_none() => return Err(Unsupported("tilde expansion")),
            '#' if word.is_none() => return Err(Unsupported("comments")),
            '!' => return Err(Unsupported("history expansion or negation (`!`)")),
            c if word_char(c) || (c == '~' || c == '#') => {
                word.get_or_insert_with(String::new).push(c);
            }
            _ => return Err(Unsupported("an unquoted special character")),
        }
    }
    end_word(&mut word, &mut tokens);
    Ok(tokens)
}

/// Parse `script` into the supported subset.
pub fn parse(script: &str) -> Result<Script, Unsupported> {
    let tokens = tokenize(script)?;
    let mut commands = Vec::new();
    let mut joiners = Vec::new();
    let mut current = SimpleCommand {
        argv: Vec::new(),
        redirects: Vec::new(),
    };
    let mut iter = tokens.into_iter().peekable();
    let mut pending_join: Option<Joiner> = None;
    let finish = |current: &mut SimpleCommand| -> Result<SimpleCommand, Unsupported> {
        if current.argv.is_empty() {
            return Err(Unsupported("an empty command"));
        }
        Ok(std::mem::replace(
            current,
            SimpleCommand {
                argv: Vec::new(),
                redirects: Vec::new(),
            },
        ))
    };
    while let Some(token) = iter.next() {
        match token {
            Token::Word(w) => {
                if current.argv.is_empty() {
                    let first = w.as_str();
                    if RESERVED.contains(&first) {
                        return Err(Unsupported(
                            "reserved words (if, for, while, functions, ...)",
                        ));
                    }
                    if REFUSED_BUILTINS.contains(&first) {
                        return Err(Unsupported(
                            "builtins that change how later commands are interpreted (eval, exec, source, cd, export, ...)",
                        ));
                    }
                    if first.contains('=') && !first.starts_with('=') {
                        return Err(Unsupported("variable assignments"));
                    }
                    if let Some(j) = pending_join.take() {
                        joiners.push(j);
                    }
                }
                current.argv.push(w);
            }
            Token::Redir(op) => {
                let target = if op == "2>&1" {
                    None
                } else {
                    match iter.next() {
                        Some(Token::Word(t)) => Some(t),
                        _ => return Err(Unsupported("a redirection without a target")),
                    }
                };
                current.redirects.push(match (op, target) {
                    (">", Some(t)) => Redirect::Out(t),
                    (">>", Some(t)) => Redirect::Append(t),
                    ("<", Some(t)) => Redirect::In(t),
                    ("2>", Some(t)) => Redirect::ErrOut(t),
                    ("2>>", Some(t)) => Redirect::ErrAppend(t),
                    _ => Redirect::ErrToOut,
                });
            }
            Token::Join(j) => {
                if current.argv.is_empty() {
                    // A trailing or doubled sequence separator is harmless; anything else is not.
                    if j == Joiner::Sequence && (pending_join.is_some() || commands.is_empty()) {
                        if commands.is_empty() && !current.redirects.is_empty() {
                            return Err(Unsupported("an empty command"));
                        }
                        continue;
                    }
                    return Err(Unsupported("an operator without a command"));
                }
                commands.push(finish(&mut current)?);
                pending_join = Some(j);
                if commands.len() > MAX_COMMANDS {
                    return Err(Unsupported("more than 16 commands"));
                }
            }
        }
    }
    if !current.argv.is_empty() {
        commands.push(finish(&mut current)?);
    } else if !current.redirects.is_empty() {
        return Err(Unsupported("an empty command"));
    } else if matches!(pending_join, Some(Joiner::And | Joiner::Or | Joiner::Pipe)) {
        return Err(Unsupported("an operator without a command"));
    }
    if commands.is_empty() {
        return Err(Unsupported("an empty script"));
    }
    if commands.len() > MAX_COMMANDS {
        return Err(Unsupported("more than 16 commands"));
    }
    Ok(Script { commands, joiners })
}

impl Script {
    /// The canonical rendering: every word re-quoted, one space between tokens. This is the
    /// text both evaluated and executed.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (i, c) in self.commands.iter().enumerate() {
            if i > 0 {
                if let Some(j) = self.joiners.get(i - 1) {
                    out.push(' ');
                    out.push_str(j.as_str());
                    out.push(' ');
                }
            }
            out.push_str(&quote_argv(&c.argv));
            for r in &c.redirects {
                let (op, target) = match r {
                    Redirect::Out(t) => (">", Some(t)),
                    Redirect::Append(t) => (">>", Some(t)),
                    Redirect::In(t) => ("<", Some(t)),
                    Redirect::ErrOut(t) => ("2>", Some(t)),
                    Redirect::ErrAppend(t) => ("2>>", Some(t)),
                    Redirect::ErrToOut => ("2>&1", None),
                };
                out.push(' ');
                out.push_str(op);
                if let Some(t) = target {
                    out.push(' ');
                    out.push_str(&quote_argv(std::slice::from_ref(t)));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_subset() {
        let s = parse("cargo fmt && cargo test --all ; npm run lint | tee 'lint log.txt' 2>&1")
            .unwrap();
        assert_eq!(s.commands.len(), 4);
        assert_eq!(s.joiners, [Joiner::And, Joiner::Sequence, Joiner::Pipe]);
        assert_eq!(s.commands[3].argv, ["tee", "lint log.txt"]);
        assert_eq!(s.commands[3].redirects, [Redirect::ErrToOut]);
        assert_eq!(
            s.render(),
            "cargo fmt && cargo test --all ; npm run lint | tee 'lint log.txt' 2>&1"
        );
        let r = parse("echo \"a b\" > out.txt\ngrep -n x < in.txt 2> err.txt").unwrap();
        assert_eq!(r.commands[0].argv, ["echo", "a b"]);
        assert_eq!(r.commands[0].redirects, [Redirect::Out("out.txt".into())]);
        assert_eq!(
            r.commands[1].redirects,
            [
                Redirect::In("in.txt".into()),
                Redirect::ErrOut("err.txt".into())
            ]
        );
        assert!(parse("cargo test;").is_ok());
    }

    #[test]
    fn everything_else_is_refused() {
        for script in [
            "echo $(touch pwned)",
            "echo `touch pwned`",
            "echo $HOME",
            "echo \"$HOME\"",
            "echo ${X}",
            "echo $((1+1))",
            "rm -rf *",
            "ls ~/.ssh",
            "sleep 10 &",
            "(cd /tmp && ls)",
            "{ ls; }",
            "cat <<EOF\nx\nEOF",
            "diff <(ls) <(ls a)",
            "ls # comment",
            "FOO=bar cargo test",
            "if true; then ls; fi",
            "eval ls",
            "source ./env.sh",
            ". ./env.sh",
            "cd /tmp && ls",
            "export X=1",
            "ls |& cat",
            "ls >| out",
            "ls 3>&1",
            "ls 'unterminated",
            "ls && ",
            "| ls",
            "ls || || ls",
            "echo a\\\nb",
            "echo !!",
            "echo \"a\\nb\"",
            "",
            "   ",
        ] {
            assert!(parse(script).is_err(), "{script:?}");
        }
    }

    #[test]
    fn quoted_specials_are_data_and_render_quoted() {
        let s = parse("echo 'a; rm -rf / $(x) `y`' \"b|c\"").unwrap();
        assert_eq!(s.commands.len(), 1);
        assert_eq!(s.commands[0].argv[1], "a; rm -rf / $(x) `y`");
        let rendered = s.render();
        assert_eq!(
            parse(&rendered).unwrap(),
            s,
            "the rendering re-parses to the same script"
        );
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut rng = fastrand::Rng::with_seed(11);
        let alphabet: Vec<char> = "ab 2>&|;'\"\\$`(){}*?~#!\n<-=".chars().collect();
        for _ in 0..5000 {
            let s: String = (0..rng.usize(0..40))
                .map(|_| alphabet[rng.usize(..alphabet.len())])
                .collect();
            if let Ok(script) = parse(&s) {
                assert!(!script.render().contains('$') || script.render().contains('\''));
                assert_eq!(parse(&script.render()).unwrap(), script, "{s:?}");
            }
        }
    }
}
