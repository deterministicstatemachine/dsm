// SPDX-License-Identifier: MIT OR Apache-2.0
//! The native methods the app declares: every `external fun` in its Kotlin
//! sources, as the symbol the JVM resolves it to (JNI's short name,
//! `Java_<class>_<method>`). An exported `Java_…` function is an entry point
//! only when one of these names it; an export no declaration names is a
//! dead-root candidate, not a root. A declaration whose symbol this map
//! cannot spell (a JVM name built from constants, an `internal` member's
//! module suffix, a multifile part class, a Java `native` method) is kept
//! with the symbol prefix every export it could be starts with: such an
//! export is Indeterminate, never a root and never a dead-root candidate.

use std::collections::BTreeMap;
use std::path::Path;

/// The native methods declared under a directory.
pub struct Declarations {
    /// Each JNI symbol, and where it is declared (`file:line`).
    pub symbols: BTreeMap<String, String>,
    /// The declarations whose symbol is not read.
    pub unread: Vec<Unread>,
}

/// A native declaration whose JNI symbol this map cannot spell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    /// What every export it could be starts with: `Java_<class>_`,
    /// `Java_<class>_<method>__` for an overload's long name, or less.
    pub prefix: String,
    /// Where it is declared, `file:line`.
    pub at: String,
    pub why: String,
}

impl Declarations {
    /// The unread declaration an exported symbol could be, if any.
    pub fn could_be(&self, exported: &str) -> Option<&Unread> {
        self.unread.iter().find(|u| exported.starts_with(&u.prefix))
    }
}

/// Every native method declared under `dir` (relative to `root`).
pub fn declared(root: &Path, dir: &str) -> Result<Declarations, String> {
    let mut out = BTreeMap::new();
    let mut unread = Vec::new();
    let mut files = Vec::new();
    walk(&root.join(dir), &mut files)?;
    files.sort();
    for (path, language) in files {
        let relative = crate::path_text(
            path.strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?,
        )?;
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{relative}: {e}"))?;
        match language {
            Language::Kotlin => {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| format!("{relative}: no file name"))?;
                for native in kotlin_natives(&text, stem).map_err(|e| format!("{relative}: {e}"))? {
                    match native {
                        Native::Read(symbol, line) => {
                            let at = format!("{relative}:{line}");
                            // An overload: the short name is still what the
                            // JVM tries first; its long name is not read.
                            if let Some(first) = out.get(&symbol) {
                                unread.push(Unread {
                                    prefix: format!("{symbol}__"),
                                    at: at.clone(),
                                    why: format!(
                                        "an overload of the native at {first}: its long JNI name carries a signature this map does not spell"
                                    ),
                                });
                                continue;
                            }
                            out.insert(symbol, at);
                        }
                        Native::Unread { prefix, line, why } => unread.push(Unread {
                            prefix,
                            at: format!("{relative}:{line}"),
                            why,
                        }),
                    }
                }
            }
            Language::Java => {
                if let Some(package) =
                    java_native_package(&text).map_err(|e| format!("{relative}: {e}"))?
                {
                    unread.push(Unread {
                        prefix: class_prefix(&package),
                        at: relative.clone(),
                        why: "a Java `native` method: this map reads Kotlin declarations"
                            .to_string(),
                    });
                }
            }
        }
    }
    Ok(Declarations {
        symbols: out,
        unread,
    })
}

/// A native method read from a Kotlin file: its symbol, or the prefix of
/// every symbol it could be and why it is not read; with its line.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Native {
    Read(String, usize),
    Unread {
        prefix: String,
        line: usize,
        why: String,
    },
}

/// The symbol prefix of every class in a package (`Java_a_b_`), or of every
/// class at all (`Java_`).
fn class_prefix(package: &str) -> String {
    if package.is_empty() {
        "Java_".to_string()
    } else {
        format!("Java_{}_", mangle(package))
    }
}

/// The two languages an Android source file under the app can be written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Language {
    Kotlin,
    Java,
}

fn walk(dir: &Path, out: &mut Vec<(std::path::PathBuf, Language)>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_dir() {
            walk(&path, out)?;
            continue;
        }
        let language = match path.extension().and_then(|e| e.to_str()) {
            Some("kt") => Language::Kotlin,
            Some("java") => Language::Java,
            _ => continue,
        };
        out.push((path, language));
    }
    Ok(())
}

/// When a Java file declares a `native` method: its package (`a/b`, empty
/// for none).
fn java_native_package(text: &str) -> Result<Option<String>, String> {
    let stripped = strip(text, Language::Java)?;
    // Words, with `$` part of a Java identifier (`native$count` is one word)
    // and `.` joining a qualified name (`a.b.c` is one word). `native` is a
    // reserved keyword (JLS 3.9): with comments, strings and characters
    // blanked, it is written nowhere but as the modifier of a native method.
    let words: Vec<&str> = stripped
        .code
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '.'))
        .filter(|w| !w.is_empty())
        .collect();
    if !words.contains(&"native") {
        return Ok(None);
    }
    let package = match words.iter().position(|w| *w == "package") {
        Some(k) => words
            .get(k + 1)
            .ok_or("a Java `package` with no name")?
            .replace('.', "/"),
        None => String::new(),
    };
    Ok(Some(package))
}

/// JNI's escaping of a class or method name into a symbol: `/` separates
/// packages and classes (`_`), and `_`, `;`, `[` and every character outside
/// ASCII letters and digits are escaped (`_1`, `_2`, `_3`, `_0xxxx`).
pub fn mangle(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => out.push(c),
            '/' => out.push('_'),
            '_' => out.push_str("_1"),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    out.push_str(&format!("_0{unit:04x}"));
                }
            }
        }
    }
    out
}

/// A string literal's value as the reader can spell it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Literal {
    /// A constant: the literal's characters, escapes decoded.
    Plain(String),
    /// A literal built with `$name` or `${…}` templates.
    Templated,
    /// A literal holding a lone UTF-16 surrogate, which no Rust string holds.
    LoneSurrogate(u32),
}

/// A file with comments, strings and character literals blanked (every
/// character kept in place, newlines kept, so lines and offsets still count),
/// and each Kotlin string literal's value by the offset of its opening quote.
struct Stripped {
    code: String,
    literals: BTreeMap<usize, Literal>,
}

/// Blanks comments, strings and character literals. Anything left open at
/// the end of the file is an error: the file does not read as its language.
fn strip(text: &str, language: Language) -> Result<Stripped, String> {
    let mut s = Stripper {
        chars: text.chars().collect(),
        at: 0,
        out: String::with_capacity(text.len()),
        language,
        literals: BTreeMap::new(),
    };
    while s.at < s.chars.len() {
        match (s.chars[s.at], s.peek(1)) {
            ('/', Some('/')) => s.line_comment(),
            ('/', Some('*')) => s.block_comment()?,
            ('"', _) => s.string()?,
            ('\'', _) => s.char_literal()?,
            (c, _) => {
                s.out.push(c);
                s.at += 1;
            }
        }
    }
    Ok(Stripped {
        code: s.out,
        literals: s.literals,
    })
}

struct Stripper {
    chars: Vec<char>,
    at: usize,
    out: String,
    language: Language,
    literals: BTreeMap<usize, Literal>,
}

impl Stripper {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// Blanks the character at the cursor and moves past it.
    fn skip(&mut self) {
        let c = self.chars[self.at];
        self.out.push(if c == '\n' { '\n' } else { ' ' });
        self.at += 1;
    }

    fn open_at_end(&self, what: &str) -> String {
        format!(
            "an unterminated {what}: the file does not read as {:?}",
            self.language
        )
    }

    fn line_comment(&mut self) {
        while self.at < self.chars.len() && self.chars[self.at] != '\n' {
            self.skip();
        }
    }

    /// A block comment. Kotlin's nest; Java's end at the first `*/`.
    fn block_comment(&mut self) -> Result<(), String> {
        let mut depth = 0usize;
        loop {
            match (self.chars.get(self.at).copied(), self.peek(1)) {
                (None, _) => return Err(self.open_at_end("`/*` comment")),
                (Some('/'), Some('*')) if depth == 0 || self.language == Language::Kotlin => {
                    depth += 1;
                    self.skip();
                    self.skip();
                }
                (Some('*'), Some('/')) => {
                    depth -= 1;
                    self.skip();
                    self.skip();
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.skip(),
            }
        }
    }

    /// A string literal, `"…"` or `"""…"""`. In Kotlin, with its `$name`
    /// and `${…}` templates, and its value recorded; a Kotlin `"""` string
    /// has no escapes, a Java text block does.
    fn string(&mut self) -> Result<(), String> {
        let start = self.at;
        let kotlin = self.language == Language::Kotlin;
        let raw = self.peek(1) == Some('"') && self.peek(2) == Some('"');
        let escapes = !raw || !kotlin;
        let quotes = if raw { 3 } else { 1 };
        for _ in 0..quotes {
            self.skip();
        }
        let mut value = Value::Text(String::new());
        loop {
            match (self.chars.get(self.at).copied(), self.peek(1), self.peek(2)) {
                (None, ..) => return Err(self.open_at_end("string")),
                (Some('"'), Some('"'), Some('"')) if raw => {
                    for _ in 0..3 {
                        self.skip();
                    }
                    break;
                }
                (Some('"'), ..) if !raw => {
                    self.skip();
                    break;
                }
                (Some('\\'), Some(_), _) if escapes => match self.escape()? {
                    Escaped::Char(c) => value.push(c),
                    Escaped::LoneSurrogate(unit) => {
                        if let Value::Text(_) = value {
                            value = Value::LoneSurrogate(unit);
                        }
                    }
                },
                (Some('$'), Some('{'), _) if kotlin => {
                    self.skip();
                    self.skip();
                    self.template()?;
                    value = Value::Templated;
                }
                (Some('$'), Some(c), _)
                    if kotlin && (c.is_alphabetic() || c == '_' || c == '`') =>
                {
                    self.skip();
                    value = Value::Templated;
                }
                (Some(c), ..) => {
                    value.push(c);
                    self.skip();
                }
            }
        }
        if kotlin {
            self.literals.insert(
                start,
                match value {
                    Value::Text(text) => Literal::Plain(text),
                    Value::Templated => Literal::Templated,
                    Value::LoneSurrogate(unit) => Literal::LoneSurrogate(unit),
                },
            );
        }
        Ok(())
    }

    /// The character a `\` escape at the cursor stands for, moving past it.
    /// Kotlin's escapes are decoded; a Java escape's character is not read.
    fn escape(&mut self) -> Result<Escaped, String> {
        let c = self.peek(1).ok_or_else(|| self.open_at_end("escape"))?;
        self.skip();
        self.skip();
        if self.language == Language::Java {
            return Ok(Escaped::Char(c));
        }
        match c {
            't' => Ok(Escaped::Char('\t')),
            'b' => Ok(Escaped::Char('\u{8}')),
            'n' => Ok(Escaped::Char('\n')),
            'r' => Ok(Escaped::Char('\r')),
            '\'' | '"' | '\\' | '$' => Ok(Escaped::Char(c)),
            'u' => {
                let unit = self.utf16_unit()?;
                match unit {
                    // A high surrogate and the low one written after it are
                    // one character.
                    0xD800..=0xDBFF => match self.low_surrogate_ahead() {
                        Some(low) => {
                            for _ in 0..6 {
                                self.skip();
                            }
                            let joined = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                            char::from_u32(joined).map(Escaped::Char).ok_or_else(|| {
                                format!("`\\u{unit:04x}\\u{low:04x}` is no character")
                            })
                        }
                        None => Ok(Escaped::LoneSurrogate(unit)),
                    },
                    0xDC00..=0xDFFF => Ok(Escaped::LoneSurrogate(unit)),
                    _ => char::from_u32(unit)
                        .map(Escaped::Char)
                        .ok_or_else(|| format!("`\\u{unit:04x}` is no character")),
                }
            }
            other => Err(format!(
                "an unknown escape `\\{other}`: the file does not read as Kotlin"
            )),
        }
    }

    /// The low surrogate a `\uDC00`–`\uDFFF` escape at the cursor writes, if
    /// one does; the cursor does not move.
    fn low_surrogate_ahead(&self) -> Option<u32> {
        let ahead: String = self.chars.get(self.at..self.at + 6)?.iter().collect();
        let digits = ahead.strip_prefix("\\u")?;
        let unit = digits
            .chars()
            .try_fold(0u32, |acc, c| Some(acc * 16 + c.to_digit(16)?))?;
        (0xDC00..=0xDFFF).contains(&unit).then_some(unit)
    }

    /// The four hex digits of a `\u` escape at the cursor, moving past them.
    fn utf16_unit(&mut self) -> Result<u32, String> {
        let digits: String = self
            .chars
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.open_at_end("`\\u` escape"))?
            .iter()
            .collect();
        let unit = u32::from_str_radix(&digits, 16)
            .map_err(|e| format!("`\\u{digits}`: {e}: the file does not read as Kotlin"))?;
        for _ in 0..4 {
            self.skip();
        }
        Ok(unit)
    }

    /// The code inside `${…}`, up to its closing brace: strings, characters
    /// and braces nest in it.
    fn template(&mut self) -> Result<(), String> {
        let mut depth = 1usize;
        loop {
            match (self.chars.get(self.at).copied(), self.peek(1)) {
                (None, _) => return Err(self.open_at_end("`${` template")),
                (Some('/'), Some('/')) => self.line_comment(),
                (Some('/'), Some('*')) => self.block_comment()?,
                (Some('"'), _) => self.string()?,
                (Some('\''), _) => self.char_literal()?,
                (Some('{'), _) => {
                    depth += 1;
                    self.skip();
                }
                (Some('}'), _) => {
                    depth -= 1;
                    self.skip();
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (Some(_), _) => self.skip(),
            }
        }
    }

    fn char_literal(&mut self) -> Result<(), String> {
        self.skip();
        loop {
            match (self.chars.get(self.at).copied(), self.peek(1)) {
                (None, _) => return Err(self.open_at_end("character literal")),
                (Some('\''), _) => {
                    self.skip();
                    return Ok(());
                }
                (Some('\\'), Some(_)) => {
                    self.skip();
                    self.skip();
                }
                _ => self.skip(),
            }
        }
    }
}

/// A string literal's value while it is read.
enum Value {
    Text(String),
    Templated,
    /// A UTF-16 unit no Rust string holds: a lone surrogate.
    LoneSurrogate(u32),
}

/// What one escape stands for.
enum Escaped {
    Char(char),
    /// A surrogate with no partner: valid in a Kotlin (UTF-16) string.
    LoneSurrogate(u32),
}

impl Value {
    fn push(&mut self, c: char) {
        if let Value::Text(text) = self {
            text.push(c);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String, usize),
    Literal(Literal),
    Open,
    Close,
    ParenOpen,
    ParenClose,
    BracketOpen,
    BracketClose,
    Lt,
    Gt,
    Dot,
    /// `:` — a supertype, a use-site target, or half of `::`.
    Colon,
    /// `;` — ends a statement written on one line with others.
    Semi,
    /// `@` opening an annotation, with its line (a label's `@`, written
    /// against its name, is no token).
    At(usize),
}

fn tokens(stripped: &Stripped) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut line = 1usize;
    let chars: Vec<char> = stripped.code.chars().collect();
    let mut at = 0usize;
    while at < chars.len() {
        if let Some(literal) = stripped.literals.get(&at) {
            out.push(Token::Literal(literal.clone()));
        }
        let c = chars[at];
        if c.is_alphabetic() || c == '_' || c == '`' {
            let mut word = String::new();
            let quoted = c == '`';
            if quoted {
                at += 1;
            }
            while at < chars.len()
                && (chars[at].is_alphanumeric() || chars[at] == '_' || (quoted && chars[at] != '`'))
            {
                word.push(chars[at]);
                at += 1;
            }
            if quoted {
                if chars.get(at) != Some(&'`') {
                    return Err(format!("line {line}: an unterminated `backtick` name: the file does not read as Kotlin"));
                }
                at += 1;
            }
            out.push(Token::Word(word, line));
            continue;
        }
        if c.is_ascii_digit() {
            // A number, with its suffix or radix letters: no token.
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            continue;
        }
        match c {
            '\n' => line += 1,
            '{' => out.push(Token::Open),
            '}' => out.push(Token::Close),
            '(' => out.push(Token::ParenOpen),
            ')' => out.push(Token::ParenClose),
            '[' => out.push(Token::BracketOpen),
            ']' => out.push(Token::BracketClose),
            '<' => out.push(Token::Lt),
            '-' if chars.get(at + 1) == Some(&'>') => at += 1,
            '>' => out.push(Token::Gt),
            '.' => out.push(Token::Dot),
            ':' => out.push(Token::Colon),
            ';' => out.push(Token::Semi),
            '@' => {
                let label = at
                    .checked_sub(1)
                    .and_then(|k| chars.get(k))
                    .is_some_and(|p| p.is_alphanumeric() || *p == '_' || *p == '`');
                if !label {
                    out.push(Token::At(line));
                }
            }
            _ => {}
        }
        at += 1;
    }
    Ok(out)
}

#[derive(Clone, Debug)]
enum Scope {
    /// A class, interface or named object, by its JVM name.
    Class(String),
    /// A companion object: `Companion` or its given name.
    Companion(String),
    /// A body that declares no class: a function, an anonymous object, a block.
    Other,
}

/// An annotation as written: its use-site target (`file`, `get`, …), its
/// dotted name, and the tokens of its arguments.
#[derive(Clone, Debug)]
struct Annotation {
    target: Option<String>,
    name: Vec<String>,
    arguments: Vec<Token>,
}

impl Annotation {
    /// Whether this is `kotlin.jvm.<simple>`, written plainly or qualified.
    fn is_jvm(&self, simple: &str) -> bool {
        let names = self.name.iter().map(String::as_str);
        names.clone().eq([simple]) || names.eq(["kotlin", "jvm", simple])
    }

    /// The single string constant the annotation is given.
    fn string_argument(&self) -> Result<String, String> {
        match self.arguments.as_slice() {
            [Token::Literal(Literal::Plain(value))] => Ok(value.clone()),
            [Token::Word(n, _), Token::Literal(Literal::Plain(value))] if n == "name" => {
                Ok(value.clone())
            }
            [Token::Literal(Literal::LoneSurrogate(unit))]
            | [Token::Word(_, _), Token::Literal(Literal::LoneSurrogate(unit))] => Err(format!(
                "@{} names a lone UTF-16 surrogate (\\u{unit:04x}), which no symbol this map spells holds",
                self.name.join(".")
            )),
            _ => Err(format!(
                "@{} is given an argument this map does not evaluate",
                self.name.join(".")
            )),
        }
    }
}

/// What stands before a declaration's keyword.
#[derive(Clone, Debug)]
enum Modifier {
    Keyword(String),
    Annotation(Annotation),
}

/// What a file's annotations say about the class its top-level
/// declarations compile into: the name `@file:JvmName` gives, the package
/// `@file:JvmPackageName` gives (each read, or why not), and where
/// `@file:JvmMultifileClass` moves them into part classes.
struct FileClass {
    name: Option<Result<String, String>>,
    package: Option<Result<String, String>>,
    multifile: Option<usize>,
}

/// Kotlin's use-site targets: `@file:…`, `@get:…` and the rest.
const USE_SITE_TARGETS: [&str; 9] = [
    "file", "property", "field", "get", "set", "receiver", "param", "setparam", "delegate",
];

/// The JNI symbols of the `external fun` declarations in one Kotlin file, with
/// their lines. `stem` is the file's name, for top-level declarations.
fn kotlin_natives(text: &str, stem: &str) -> Result<Vec<Native>, String> {
    let stripped = strip(text, Language::Kotlin)?;
    let toks = tokens(&stripped)?;
    let mut package = String::new();
    let mut file = FileClass {
        name: None,
        package: None,
        multifile: None,
    };
    let mut scopes: Vec<Scope> = Vec::new();
    // The scope the next `{` opens, and the parenthesis depth it was named at.
    let mut pending: Option<(Scope, usize)> = None;
    let mut modifiers: Vec<Modifier> = Vec::new();
    let mut paren = 0usize;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < toks.len() {
        match &toks[at] {
            Token::At(line) => {
                let (read, next) = annotations(&toks, at)?;
                for a in read {
                    match a.target.as_deref() {
                        Some("file") => file_annotation(&a, *line, &mut file),
                        _ => modifiers.push(Modifier::Annotation(a)),
                    }
                }
                at = next;
                continue;
            }
            Token::Word(w, _) if MODIFIERS.contains(&w.as_str()) => {
                modifiers.push(Modifier::Keyword(w.clone()));
                at += 1;
                continue;
            }
            Token::Word(w, line) if w == "package" && scopes.is_empty() => {
                let (name, next) = dotted(&toks, at + 1)
                    .ok_or_else(|| format!("line {line}: a `package` with no name"))?;
                package = name.join("/");
                at = next;
                modifiers.clear();
                continue;
            }
            Token::Word(w, _) if w == "class" || w == "interface" => {
                // `Name::class` is a class literal, not a declaration.
                let literal =
                    at >= 2 && toks[at - 2] == Token::Colon && toks[at - 1] == Token::Colon;
                match toks.get(at + 1) {
                    Some(Token::Word(name, _)) if !literal => {
                        pending = Some((Scope::Class(name.clone()), paren));
                    }
                    _ => {}
                }
            }
            Token::Word(w, _) if w == "object" => {
                let companion = modifiers
                    .iter()
                    .any(|m| matches!(m, Modifier::Keyword(k) if k == "companion"));
                let scope = match (companion, toks.get(at + 1)) {
                    (c, Some(Token::Word(name, _))) if c => Scope::Companion(name.clone()),
                    (c, _) if c => Scope::Companion("Companion".to_string()),
                    // `object : Super { … }` and `object { … }` are anonymous.
                    (_, Some(Token::Word(name, _))) => Scope::Class(name.clone()),
                    _ => Scope::Other,
                };
                pending = Some((scope, paren));
            }
            Token::Word(w, line) if w == "fun" => {
                if matches!(pending, Some((_, depth)) if depth == paren) {
                    pending = None;
                }
                let external = modifiers
                    .iter()
                    .any(|m| matches!(m, Modifier::Keyword(k) if k == "external"));
                if external {
                    let class = owner(&package, &scopes, &file, stem, &modifiers);
                    out.push(native(&toks, at, class, &modifiers, *line));
                }
            }
            Token::Word(w, _) if w == "val" || w == "var" => {
                if matches!(pending, Some((_, depth)) if depth == paren) {
                    pending = None;
                }
            }
            Token::ParenOpen => paren += 1,
            Token::ParenClose => {
                paren = paren.checked_sub(1).ok_or_else(|| {
                    "a `)` closes nothing: the file does not read as Kotlin".to_string()
                })?
            }
            Token::Open => {
                let scope = match pending.take() {
                    Some((scope, depth)) if depth == paren => scope,
                    // A lambda inside a declaration's parentheses: the
                    // declaration's own body is still to come.
                    Some(waiting) => {
                        pending = Some(waiting);
                        Scope::Other
                    }
                    None => Scope::Other,
                };
                scopes.push(scope);
            }
            Token::Close => {
                scopes.pop().ok_or_else(|| {
                    "a `}` closes nothing: the file does not read as Kotlin".to_string()
                })?;
            }
            Token::Word(..)
            | Token::Literal(_)
            | Token::BracketOpen
            | Token::BracketClose
            | Token::Lt
            | Token::Gt
            | Token::Dot
            | Token::Colon
            | Token::Semi => {}
        }
        modifiers.clear();
        at += 1;
    }
    if paren != 0 || !scopes.is_empty() {
        return Err(format!(
            "{paren} `(` and {} `{{` are left open at the end: the file does not read as Kotlin",
            scopes.len()
        ));
    }
    Ok(out)
}

/// What one `external fun` at `at` is: its JNI symbol, from its class and
/// its JVM name (`@JvmName`'s, or its own); or, when either is not read, the
/// prefix every symbol it could be starts with.
fn native(toks: &[Token], at: usize, class: Class, modifiers: &[Modifier], line: usize) -> Native {
    let class = match class {
        Class::Read(class) => class,
        Class::Unread { prefix, why } => return Native::Unread { prefix, line, why },
    };
    let prefix = format!("Java_{}_", mangle(&class));
    let unread = |prefix: String, why: String| Native::Unread { prefix, line, why };
    let name = match fun_name(toks, at + 1) {
        FunHeader::Named(name) => name,
        FunHeader::Anonymous => {
            return unread(prefix, "an `external fun` with no name".to_string())
        }
        FunHeader::Unread(why) => return unread(prefix, why),
    };
    let renamed = modifiers.iter().find_map(|m| match m {
        Modifier::Annotation(a) if a.is_jvm("JvmName") => Some(a.string_argument()),
        _ => None,
    });
    let internal = modifiers
        .iter()
        .any(|m| matches!(m, Modifier::Keyword(k) if k == "internal"));
    let method = match (renamed, internal) {
        (Some(Ok(jvm)), _) => jvm,
        (Some(Err(why)), _) => return unread(prefix, why),
        // Kotlin appends the module's name to an internal member's JVM name.
        (None, i) if i => {
            return unread(
                format!("{prefix}{}", mangle(&name)),
                "an `internal` native's JVM name carries its module's name".to_string(),
            )
        }
        (None, _) => name,
    };
    Native::Read(format!("{prefix}{}", mangle(&method)), line)
}

/// A file annotation that names the file's class or its package.
fn file_annotation(a: &Annotation, line: usize, file: &mut FileClass) {
    if a.is_jvm("JvmName") {
        file.name = Some(a.string_argument());
    } else if a.is_jvm("JvmPackageName") {
        file.package = Some(a.string_argument().map(|p| p.replace('.', "/")));
    } else if a.is_jvm("JvmMultifileClass") {
        file.multifile = Some(line);
    }
}

/// The annotations an `@` at `at` opens — `@Name`, `@a.b.Name(args)`,
/// `@target:Name`, `@[A B(args)]` — and the token after them.
fn annotations(toks: &[Token], at: usize) -> Result<(Vec<Annotation>, usize), String> {
    let mut next = at + 1;
    let target = match (toks.get(next), toks.get(next + 1)) {
        (Some(Token::Word(w, _)), Some(Token::Colon)) if USE_SITE_TARGETS.contains(&w.as_str()) => {
            next += 2;
            Some(w.clone())
        }
        _ => None,
    };
    let mut out = Vec::new();
    if toks.get(next) == Some(&Token::BracketOpen) {
        next += 1;
        loop {
            match toks.get(next) {
                Some(Token::BracketClose) => {
                    next += 1;
                    break;
                }
                Some(Token::Word(..)) => {
                    let (a, after) = one_annotation(toks, next, &target)?;
                    out.push(a);
                    next = after;
                }
                _ => return Err("an `@[` annotation list that does not read as Kotlin".to_string()),
            }
        }
    } else {
        let (a, after) = one_annotation(toks, next, &target)?;
        out.push(a);
        next = after;
    }
    Ok((out, next))
}

fn one_annotation(
    toks: &[Token],
    at: usize,
    target: &Option<String>,
) -> Result<(Annotation, usize), String> {
    let (name, named) = dotted(toks, at).ok_or_else(|| {
        "an `@` that names no annotation: the file does not read as Kotlin".to_string()
    })?;
    // Type arguments: `@Generic<String>(…)`.
    let after = match toks.get(named) {
        Some(Token::Lt) => angle_end(toks, named)? + 1,
        _ => named,
    };
    let (arguments, next) = match toks.get(after) {
        Some(Token::ParenOpen) => {
            let close = paren_end(toks, after, "an annotation's arguments")?;
            (toks[after + 1..close].to_vec(), close + 1)
        }
        _ => (Vec::new(), after),
    };
    Ok((
        Annotation {
            target: target.clone(),
            name,
            arguments,
        },
        next,
    ))
}

/// A dotted name starting at `at` (`a.b.C`, across lines), and the token
/// after it.
fn dotted(toks: &[Token], at: usize) -> Option<(Vec<String>, usize)> {
    let Some(Token::Word(first, _)) = toks.get(at) else {
        return None;
    };
    let mut names = vec![first.clone()];
    let mut next = at + 1;
    while let (Some(Token::Dot), Some(Token::Word(part, _))) = (toks.get(next), toks.get(next + 1))
    {
        names.push(part.clone());
        next += 2;
    }
    Some((names, next))
}

/// The `)` closing the `(` at `open`. A brace inside is refused: neither an
/// annotation's arguments nor a type holds one.
fn paren_end(toks: &[Token], open: usize, what: &str) -> Result<usize, String> {
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match t {
            Token::ParenOpen => depth += 1,
            Token::ParenClose => {
                depth -= 1;
                if depth == 0 {
                    return Ok(k);
                }
            }
            Token::Open | Token::Close => {
                return Err(format!(
                    "a brace inside {what}: the file does not read as Kotlin"
                ))
            }
            _ => {}
        }
    }
    Err(format!(
        "the `(` of {what} is never closed: the file does not read as Kotlin"
    ))
}

/// The `>` closing the `<` at `open`, across nested `<…>` and `(…)`.
fn angle_end(toks: &[Token], open: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match t {
            Token::Lt => depth += 1,
            Token::Gt => {
                depth -= 1;
                if depth == 0 {
                    return Ok(k);
                }
            }
            Token::Open | Token::Close | Token::Semi => break,
            _ => {}
        }
    }
    Err("a `<` in a `fun` header is never closed: the file does not read as Kotlin".to_string())
}

/// What a `fun` header declares.
enum FunHeader {
    Named(String),
    /// An anonymous function: its `(` comes before any name.
    Anonymous,
    /// A header this map does not read, and why.
    Unread(String),
}

/// The name a `fun` header starting at `start` declares: after any type
/// parameters and receiver type (a parenthesized one included), the last
/// name before its parameters.
fn fun_name(toks: &[Token], start: usize) -> FunHeader {
    let mut at = start;
    let mut name: Option<&String> = None;
    loop {
        match toks.get(at) {
            Some(Token::Lt) => match angle_end(toks, at) {
                Ok(end) => at = end + 1,
                Err(why) => return FunHeader::Unread(why),
            },
            Some(Token::Word(w, _)) => {
                name = Some(w);
                at += 1;
            }
            Some(Token::Dot) => at += 1,
            // An annotated receiver type: `fun @A T.name()`.
            Some(Token::At(_)) => match annotations(toks, at) {
                Ok((_, next)) => at = next,
                Err(why) => return FunHeader::Unread(why),
            },
            Some(Token::ParenOpen) => {
                let close = match paren_end(toks, at, "a `fun` header") {
                    Ok(close) => close,
                    Err(why) => return FunHeader::Unread(why),
                };
                // A parenthesized receiver type (`fun (A.() -> B).name()`) is
                // followed by `.`; the parameter list is not.
                if toks.get(close + 1) == Some(&Token::Dot) {
                    name = None;
                    at = close + 2;
                    continue;
                }
                return match name {
                    Some(n) => FunHeader::Named(n.clone()),
                    None => FunHeader::Anonymous,
                };
            }
            other => {
                return FunHeader::Unread(format!(
                    "a `fun` header this map does not read (at {other:?})"
                ))
            }
        }
    }
}

/// Kotlin's modifier keywords: any of them, in any order, may stand among a
/// declaration's annotations before its keyword.
const MODIFIERS: [&str; 28] = [
    "public",
    "private",
    "protected",
    "internal",
    "open",
    "final",
    "abstract",
    "sealed",
    "override",
    "lateinit",
    "const",
    "data",
    "inner",
    "enum",
    "annotation",
    "companion",
    "external",
    "inline",
    "noinline",
    "crossinline",
    "tailrec",
    "operator",
    "infix",
    "suspend",
    "actual",
    "expect",
    "value",
    "vararg",
];

/// The class Kotlin compiles a file's top-level declarations into when no
/// `@file:JvmName` names it: the file's name as a Java identifier (every
/// character that is not a letter or digit becomes `_`), its first letter
/// upper-cased, then `Kt`.
fn facade_name(stem: &str) -> String {
    let sanitized: String = stem
        .chars()
        .map(|c| {
            if c.is_alphabetic() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut chars = sanitized.chars();
    let base = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "_".to_string(),
    };
    format!("{base}Kt")
}

/// The JVM class a native method is declared on, or the prefix of every
/// class it could be.
enum Class {
    Read(String),
    Unread { prefix: String, why: String },
}

/// The class a native is declared on: the enclosing classes joined with
/// `$`; in a companion object, the outer class when the method is
/// `@JvmStatic`, the companion's own class otherwise; at top level, the
/// file's class. Inside a function or an anonymous object the compiler
/// numbers the class, which is not read.
fn owner(
    package: &str,
    scopes: &[Scope],
    file: &FileClass,
    stem: &str,
    modifiers: &[Modifier],
) -> Class {
    let jvm_static = modifiers
        .iter()
        .any(|m| matches!(m, Modifier::Annotation(a) if a.is_jvm("JvmStatic")));
    let qualified = |class: &str| {
        if package.is_empty() {
            class.to_string()
        } else {
            format!("{package}/{class}")
        }
    };
    let mut names: Vec<String> = Vec::new();
    for scope in scopes {
        match scope {
            Scope::Class(name) | Scope::Companion(name) => names.push(name.clone()),
            Scope::Other => {
                let prefix = if names.is_empty() {
                    class_prefix(package)
                } else {
                    format!("Java_{}_00024", mangle(&qualified(&names.join("$"))))
                };
                return Class::Unread {
                    prefix,
                    why: "a native inside a function or an anonymous object: its class's name is numbered by the compiler".to_string(),
                };
            }
        }
    }
    if matches!(scopes.last(), Some(Scope::Companion(_))) && jvm_static {
        names.pop();
    }
    if !names.is_empty() {
        return Class::Read(qualified(&names.join("$")));
    }
    // Top level: the file's class.
    let package = match &file.package {
        Some(Ok(p)) => p.clone(),
        Some(Err(why)) => {
            return Class::Unread {
                prefix: "Java_".to_string(),
                why: format!("@file:JvmPackageName: {why}"),
            }
        }
        None => package.to_string(),
    };
    let facade = match &file.name {
        Some(Ok(name)) => name.clone(),
        Some(Err(why)) => {
            return Class::Unread {
                prefix: class_prefix(&package),
                why: format!("@file:JvmName: {why}"),
            }
        }
        None => facade_name(stem),
    };
    let class = if package.is_empty() {
        facade
    } else {
        format!("{package}/{facade}")
    };
    match file.multifile {
        Some(at) => Class::Unread {
            prefix: format!("Java_{}", mangle(&class)),
            why: format!("a top-level native in a @file:JvmMultifileClass file (line {at}): it lives in a part class this map does not name"),
        },
        None => Class::Read(class),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangling_escapes_underscores_and_nested_classes() {
        assert_eq!(
            mangle("com/dsm/wallet/bridge/UnifiedNativeApi"),
            "com_dsm_wallet_bridge_UnifiedNativeApi"
        );
        assert_eq!(mangle("get_session"), "get_1session");
        assert_eq!(mangle("com/a/Outer$Inner"), "com_a_Outer_00024Inner");
    }

    #[test]
    fn natives_are_read_from_objects_and_companions() -> Result<(), String> {
        let text = r#"
package com.dsm.wallet.bridge

// external fun commented(): Int
internal object UnifiedNativeApi {
    private val tag = "external fun inString(): Int { }"
    @JvmStatic external fun getSessionSnapshot(): ByteArray
    @JvmStatic
    external fun set_fatal(message: String)
}

class Bridge(private val c: Context) {
    fun helper() { val x = 1 }
    companion object {
        @JvmStatic external fun viaOuter(): Int
        external fun onCompanion(): Int
    }
}
"#;
        let got = kotlin_natives(text, "UnifiedNativeApi")?;
        assert_eq!(
            symbols(text, "UnifiedNativeApi")?,
            vec![
                "Java_com_dsm_wallet_bridge_UnifiedNativeApi_getSessionSnapshot",
                "Java_com_dsm_wallet_bridge_UnifiedNativeApi_set_1fatal",
                "Java_com_dsm_wallet_bridge_Bridge_viaOuter",
                "Java_com_dsm_wallet_bridge_Bridge_00024Companion_onCompanion",
            ]
        );
        assert_eq!(
            got.first(),
            Some(&Native::Read(
                "Java_com_dsm_wallet_bridge_UnifiedNativeApi_getSessionSnapshot".to_string(),
                7
            ))
        );
        Ok(())
    }

    #[test]
    fn unbalanced_kotlin_is_refused() -> Result<(), String> {
        for text in [
            "object A { external fun f()",
            "object A { } }",
            "object A { fun f() ) }",
        ] {
            match kotlin_natives(text, "A") {
                Err(e) => assert!(e.contains("does not read as Kotlin"), "{text}: {e}"),
                Ok(read) => return Err(format!("{text:?} was read as {read:?}")),
            }
        }
        Ok(())
    }

    #[test]
    fn modifiers_in_any_order_and_anonymous_objects_are_read() -> Result<(), String> {
        let text = "package a.b; import c.d\nobject O {\n    external public fun first(): Int\n    @JvmStatic open external fun second(): Int\n    val listener = object : Runnable { override fun run() {} }\n    val s = \"${ f(/* } */ 1) }\"\n    public external fun third(): Int\n}\n";
        assert_eq!(
            symbols(text, "O")?,
            vec!["Java_a_b_O_first", "Java_a_b_O_second", "Java_a_b_O_third"]
        );
        Ok(())
    }

    #[test]
    fn a_top_level_native_belongs_to_the_file_class() -> Result<(), String> {
        let got = kotlin_natives("package a.b\nexternal fun top(): Int\n", "Natives")?;
        assert_eq!(
            got,
            vec![Native::Read("Java_a_b_NativesKt_top".to_string(), 2)]
        );
        Ok(())
    }

    #[test]
    fn java_native_methods_are_seen_and_strings_are_not() -> Result<(), String> {
        assert_eq!(
            java_native_package("package a.b;\nclass A { public static native int f(); }")?,
            Some("a/b".to_string())
        );
        assert_eq!(
            java_native_package("class A { // native\n String s = \"native\"; }")?,
            None
        );
        // A qualified name holding the word is one word, not the keyword.
        assert_eq!(
            java_native_package("import com.example.nativex.Lib;\nclass A {}")?,
            None
        );
        // `$` is part of a Java identifier; Java comments do not nest.
        assert_eq!(java_native_package("class A { int native$count; }")?, None);
        assert_eq!(
            java_native_package("class A { /* /* */ native void f(); }")?,
            Some(String::new())
        );
        Ok(())
    }

    /// The symbols a file's natives read as; an unread one is an error here.
    fn symbols(text: &str, stem: &str) -> Result<Vec<String>, String> {
        kotlin_natives(text, stem)?
            .into_iter()
            .map(|n| match n {
                Native::Read(symbol, _) => Ok(symbol),
                Native::Unread { prefix, why, .. } => Err(format!("unread {prefix}: {why}")),
            })
            .collect()
    }

    /// The prefixes and reasons of a file's unread natives; a read one is an
    /// error here.
    fn unread(text: &str, stem: &str) -> Result<Vec<(String, String)>, String> {
        kotlin_natives(text, stem)?
            .into_iter()
            .map(|n| match n {
                Native::Unread { prefix, why, .. } => Ok((prefix, why)),
                Native::Read(symbol, _) => Err(format!("read as {symbol}")),
            })
            .collect()
    }

    #[test]
    fn dotted_names_span_lines_and_annotations_are_qualified() -> Result<(), String> {
        let text = "package a\n    .b\nobject O {\n    @java.lang.Deprecated(\"x\") external fun first(): Int\n    @get:Synchronized @[Suppress(\"y\") Keep] external fun second(): Int\n}\nclass C {\n    companion object {\n        @kotlin.jvm.JvmStatic external fun third(): Int\n    }\n}\n";
        assert_eq!(
            symbols(text, "O")?,
            vec!["Java_a_b_O_first", "Java_a_b_O_second", "Java_a_b_C_third"]
        );
        Ok(())
    }

    #[test]
    fn generic_and_extension_natives_are_named_by_their_name() -> Result<(), String> {
        let text = "object O {\n    external fun <T> g(x: T): Int\n    external fun <T : () -> Unit> List<T>.h(): Int\n    @JvmName(\"renamed\") external fun i(): Int\n}\n";
        assert_eq!(
            symbols(text, "O")?,
            vec!["Java_O_g", "Java_O_h", "Java_O_renamed"]
        );
        Ok(())
    }

    #[test]
    fn natives_are_read_inside_parentheses_labels_and_class_literals() -> Result<(), String> {
        // A lambda in a constructor's parentheses does not take the class's
        // body; a label's `@` is no annotation; `O::class` declares nothing.
        let text = "class C(val f: () -> Int = { 1 }) {\n    val k = C::class.java\n    fun g() { run loop@{ return@loop } }\n    external fun n(): Int\n}\n";
        assert_eq!(symbols(text, "C")?, vec!["Java_C_n"]);
        // In an anonymous object the class is numbered: every class of the
        // package, or of the enclosing class, is what it could be.
        let inside = unread(
            "package p\nfun main() { run(object { external fun hidden() }) }\nclass O { fun f() { object { external fun g() } } }\n",
            "M",
        )?;
        let prefixes: Vec<&str> = inside.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(prefixes, vec!["Java_p_", "Java_p_O_00024"]);
        assert!(inside[0].1.contains("anonymous object"));
        Ok(())
    }

    #[test]
    fn the_file_class_is_named_as_kotlin_names_it() -> Result<(), String> {
        assert_eq!(
            symbols(
                "@file:JvmName(\"Bridge\")\npackage a\nexternal fun f()\n",
                "x"
            )?,
            vec!["Java_a_Bridge_f"]
        );
        assert_eq!(
            symbols("package a\nexternal fun f()\n", "natives")?,
            vec!["Java_a_NativesKt_f"]
        );
        assert_eq!(
            symbols("package a\nexternal fun f()\n", "my-file")?,
            vec!["Java_a_My_1fileKt_f"]
        );
        assert_eq!(
            symbols(
                "@file:JvmPackageName(\"c.d\")\npackage a\nexternal fun f()\n",
                "x"
            )?,
            vec!["Java_c_d_XKt_f"]
        );
        // What is not read keeps the prefix of every symbol it could be.
        for (text, prefix, why) in [
            (
                "@file:JvmMultifileClass\n@file:JvmName(\"U\")\npackage a\nexternal fun f()\n",
                "Java_a_U",
                "part class",
            ),
            (
                "package a\nobject O { internal external fun f() }\n",
                "Java_a_O_f",
                "module",
            ),
            (
                "@file:JvmName(\"$x\")\npackage a\nexternal fun f()\n",
                "Java_a_",
                "does not evaluate",
            ),
            (
                "package a\nobject O { @JvmName(\"a\" + \"b\") external fun f() }\n",
                "Java_a_O_",
                "does not evaluate",
            ),
        ] {
            let got = unread(text, "x")?;
            assert_eq!(got.len(), 1, "{text}");
            assert_eq!(got[0].0, prefix, "{text}");
            assert!(got[0].1.contains(why), "{text}: {}", got[0].1);
        }
        Ok(())
    }

    #[test]
    fn generic_annotations_and_parenthesized_receivers_are_read() -> Result<(), String> {
        let text = "object O {\n    @Generic<String>(\"x\") @JvmName(\"kept\") external fun a(): Int\n    external fun ((Int) -> Unit).b(): Int\n    external fun @Receiver String.c(): Int\n}\n";
        assert_eq!(
            symbols(text, "O")?,
            vec!["Java_O_kept", "Java_O_b", "Java_O_c"]
        );
        Ok(())
    }

    #[test]
    fn surrogate_pairs_decode_and_a_lone_surrogate_is_kept_unread() -> Result<(), String> {
        // `\uD83D\uDE00` is one character; a JvmName holding it is spelled.
        assert_eq!(
            symbols(
                "object O { @JvmName(\"a\\uD83D\\uDE00\") external fun f() }\n",
                "O"
            )?,
            vec!["Java_O_a_0d83d_0de00"]
        );
        // A lone surrogate is valid Kotlin and no Rust string: unread.
        let got = unread(
            "object O { @JvmName(\"a\\uD83D\") external fun f() }\n",
            "O",
        )?;
        assert_eq!(got.len(), 1);
        assert!(got[0].1.contains("lone UTF-16 surrogate"), "{}", got[0].1);
        Ok(())
    }

    #[test]
    fn an_export_an_unread_declaration_could_be_is_found_by_prefix() {
        let declared = Declarations {
            symbols: BTreeMap::new(),
            unread: vec![Unread {
                prefix: "Java_a_O_f".to_string(),
                at: "O.kt:1".to_string(),
                why: "an `internal` native".to_string(),
            }],
        };
        assert!(declared.could_be("Java_a_O_f_00024app").is_some());
        assert!(declared.could_be("Java_a_O_g").is_none());
    }

    #[test]
    fn templates_nest_strings_and_open_literals_are_refused() -> Result<(), String> {
        // A `}` inside a string inside a template does not close the template.
        let text =
            "object A {\n    val s = \"${ \"}\" }\"\n    @JvmStatic external fun f(): Int\n}\n";
        let got = kotlin_natives(text, "A")?;
        assert_eq!(got, vec![Native::Read("Java_A_f".to_string(), 3)]);
        for open in [
            "val s = \"abc",
            "/* never closed",
            "val c = 'x",
            "val `name = 1",
        ] {
            match kotlin_natives(open, "A") {
                Err(e) => assert!(e.contains("does not read as Kotlin"), "{open}: {e}"),
                Ok(read) => return Err(format!("{open:?} was read as {read:?}")),
            }
        }
        Ok(())
    }
}
