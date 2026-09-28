// SPDX-License-Identifier: MIT OR Apache-2.0
//! A definition's canonical token text: what its hash covers. Whitespace,
//! comments and doc comments are not part of it; every token is.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::str::FromStr;

pub fn canonical(source: &str) -> Result<String, String> {
    let stream = TokenStream::from_str(source).map_err(|e| format!("not a token stream: {e}"))?;
    let mut out = String::new();
    write_stream(stream, &mut out);
    Ok(out)
}

fn write_stream(stream: TokenStream, out: &mut String) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut at = 0usize;
    while at < trees.len() {
        match doc_attribute_len(&trees, at) {
            Some(len) => at += len,
            None => {
                write_tree(&trees[at], out);
                at += 1;
            }
        }
    }
}

/// The token count of a `#[doc = "…"]` or `#![doc = "…"]` attribute starting
/// at `at` (what `///` and `//!` lex to), or `None` when none starts there.
fn doc_attribute_len(trees: &[TokenTree], at: usize) -> Option<usize> {
    let hash = matches!(trees.get(at), Some(TokenTree::Punct(p)) if p.as_char() == '#');
    let bang = matches!(trees.get(at + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
    let group_at = at + 1 + usize::from(bang);
    let doc = matches!(
        trees.get(group_at),
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket
            && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(i)) if i == "doc")
    );
    (hash && doc).then_some(group_at + 1 - at)
}

fn write_tree(tree: &TokenTree, out: &mut String) {
    match tree {
        TokenTree::Group(g) => {
            let (open, close) = match g.delimiter() {
                Delimiter::Parenthesis => ("(", ")"),
                Delimiter::Brace => ("{", "}"),
                Delimiter::Bracket => ("[", "]"),
                Delimiter::None => ("", ""),
            };
            out.push_str(open);
            out.push(' ');
            write_stream(g.stream(), out);
            out.push_str(close);
            out.push(' ');
        }
        TokenTree::Ident(i) => {
            out.push_str(&i.to_string());
            out.push(' ');
        }
        TokenTree::Punct(p) => {
            out.push(p.as_char());
            if p.spacing() == proc_macro2::Spacing::Alone {
                out.push(' ');
            }
        }
        TokenTree::Literal(l) => {
            out.push_str(&l.to_string());
            out.push(' ');
        }
    }
}

/// Names captured by inline format arguments (`format!("SELECT {COLS} …")`)
/// in the string literals of `source`. The index records no reference for
/// them, so the map reads them here. `{{` is an escaped brace, not a capture.
pub fn format_captures(source: &str) -> Result<Vec<String>, String> {
    let stream = TokenStream::from_str(source).map_err(|e| format!("not a token stream: {e}"))?;
    let mut out = Vec::new();
    collect_captures(stream, &mut out);
    Ok(out)
}

fn collect_captures(stream: TokenStream, out: &mut Vec<String>) {
    for tree in stream {
        match tree {
            TokenTree::Group(g) => collect_captures(g.stream(), out),
            TokenTree::Literal(l) => {
                let text = l.to_string();
                if text.starts_with('"') || text.starts_with("r\"") || text.starts_with("r#") {
                    captures_in(&text, out);
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
}

fn captures_in(text: &str, out: &mut Vec<String>) {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0usize;
    while at < chars.len() {
        if chars[at] != '{' {
            at += 1;
            continue;
        }
        if chars.get(at + 1) == Some(&'{') {
            at += 2;
            continue;
        }
        let mut end = at + 1;
        while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        let name: String = chars[at + 1..end].iter().collect();
        let starts_like_a_name = name
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_');
        if starts_like_a_name && matches!(chars.get(end), Some('}') | Some(':')) {
            out.push(name);
        }
        at = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_format_arguments_are_captures() -> Result<(), String> {
        let found = format_captures(
            r#"fn q() { format!("SELECT {COLS} FROM t WHERE k = {key:?} {{literal}} {0} {}", 1) }"#,
        )?;
        assert_eq!(found, vec!["COLS".to_string(), "key".to_string()]);
        Ok(())
    }

    #[test]
    fn layout_and_comments_do_not_count() -> Result<(), String> {
        let a = canonical("fn f(x: u8) -> u8 { x + 1 }")?;
        let b = canonical(
            "/// Adds one.\nfn f( x : u8 )\n    -> u8 {\n    // the step\n    x + /* one */ 1\n}",
        )?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn every_token_counts() -> Result<(), String> {
        assert_ne!(
            canonical("fn f(x: u8) -> u8 { x + 1 }")?,
            canonical("fn f(x: u8) -> u8 { x + 2 }")?
        );
        assert_ne!(canonical("a -= b")?, canonical("a - = b")?);
        assert_ne!(canonical("#[inline] fn f() {}")?, canonical("fn f() {}")?);
        Ok(())
    }

    #[test]
    fn inner_doc_comments_do_not_count() -> Result<(), String> {
        assert_eq!(
            canonical("mod m { //! About m.\n fn g() {} }")?,
            canonical("mod m { fn g() {} }")?
        );
        Ok(())
    }

    #[test]
    fn unbalanced_text_is_an_error() {
        assert!(matches!(canonical("fn f( {"), Err(e) if e.starts_with("not a token stream")));
    }
}
