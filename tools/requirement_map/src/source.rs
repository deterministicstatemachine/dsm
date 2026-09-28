// SPDX-License-Identifier: MIT OR Apache-2.0
//! A source file read as Rust: where a function's own text begins and ends,
//! whether it takes `self`, the trait an impl header names, how each name in
//! a path is used (constructed, dispatched on, only named), the names written
//! in call position, what an item's text begins with, and what a file uses
//! from other crates. The file is parsed with syn; a macro invocation's
//! tokens are read as items, expressions or statements when they parse as
//! one of them. Positions are the index's: 0-based lines, UTF-8 byte columns.
//!
//! Tokens a macro invocation holds that do not parse (a `macro_rules!` body,
//! a macro's own syntax) are read token by token, and only in the direction
//! that adds uncertainty: every name followed by `(…)` there is a call
//! candidate, every name after a crate's name is a name used from it. They
//! never supply construction or dispatch evidence.
//!
//! Nothing here is call-graph evidence on its own. The graph's edges come
//! from the index; these readings correct an extent the index reported
//! wrongly, qualify a reference the index recorded, or mark what the index
//! cannot see as undecided.

use crate::index::Position;
use proc_macro2::{Delimiter, LineColumn, Spacing, Span, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// A name as Rust means it: a raw identifier (`r#type`) is `type`.
fn name_of(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

/// Rust's strict and reserved keywords (the Reference, "Keywords"), the two
/// literal keywords left out: in tokens read one by one, a keyword before
/// `(…)` (`if (…)`, `match (…)`) is syntax, not a call.
const KEYWORDS: [&str; 46] = [
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "type", "unsafe", "use",
    "where", "while", "abstract", "become", "box", "do", "final", "macro", "override", "priv",
    "typeof", "unsized",
];

/// What the token at a position is part of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtPosition {
    /// Inside `#[path…]`, by the attribute's path.
    InAttribute(String),
    /// The name of a macro invocation (`name!`).
    MacroCall(String),
    /// Anything else.
    Other,
    /// No token starts there.
    NoToken,
}

/// What a function's first parameter is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receiver {
    /// `self` in any form: the function runs on a value.
    TakesSelf,
    /// No `self`: an associated function, run through the type.
    NoSelf,
    /// No function is written with its name there.
    Unread,
}

/// Whether a type is a unit struct (`struct T;`), whose bare name is a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeShape {
    UnitStruct,
    Other,
}

/// What a reference to a type does where it is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// Makes a value of it (literal, constructor, path call, unit value).
    Constructs,
    /// Dispatches on it without a value: a call's type argument
    /// (`f::<T>()`) or a qualified path's self type (`<T as Trait>::f()`).
    TypeArgument,
    /// Only names it (a type annotation, a bound, a generic argument, a
    /// pattern).
    Names,
    /// No name in a path starts at the position (or it is in tokens that do
    /// not parse, which supply no evidence).
    NoToken,
}

/// An `impl … { }` header: from `impl` to just before the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub start: Position,
    pub end: Position,
    /// Where the trait's name is written; `None` for an inherent impl.
    pub trait_name: Option<Position>,
}

/// What an item's text begins with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Head {
    /// A macro invocation: the items share the invocation's extent.
    MacroCall,
    /// Anything else.
    Other,
    /// No token at all inside the extent.
    Absent,
}

/// How a name in call position is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Form {
    /// `name(…)`
    Bare,
    /// `receiver.name(…)`
    Method,
    /// `Qualifier::name(…)`, with the segment just before the name when it
    /// is a plain name (none for `<T as Trait>::name(…)` or `T::<A>::name(…)`).
    Path(Option<String>),
}

/// A name written in call position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub at: Position,
    pub name: String,
    pub form: Form,
}

/// How a name in a path is used, before the type's shape is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathUse {
    Constructs,
    TypeArgument,
    Names,
    /// The last segment of a path used as a value: a unit struct's value, or
    /// only a name.
    Value,
}

/// A function written in the file.
struct FnRead {
    extent: (Position, Position),
    receiver: Receiver,
}

/// An item-level node: an item, an associated item or a statement macro.
struct Node {
    start: Position,
    end: Position,
    head: Head,
}

/// Everything read from the file's syntax, by position.
#[derive(Default)]
struct Syntax {
    fns: BTreeMap<Position, FnRead>,
    /// Impl blocks: the header and the body's extent.
    impls: Vec<(Header, Position, Position)>,
    uses: BTreeMap<Position, PathUse>,
    calls: Vec<Call>,
    nodes: Vec<Node>,
    /// Attributes' extents, with their paths.
    attributes: Vec<(Position, Position, String)>,
    /// Where each macro invocation's name is written, and the name.
    macro_names: BTreeMap<Position, String>,
    /// `mod name;` declarations.
    modules: BTreeSet<String>,
    functions: BTreeSet<String>,
    /// Paths through a crate: its name, and every name after it.
    crate_paths: Vec<(String, Vec<String>)>,
    /// `use` trees: their first name, and every name in them.
    use_trees: Vec<(String, Vec<String>)>,
    /// Macro invocations whose tokens parse as nothing: where the macro is
    /// named, its tokens, and why each reading failed.
    unparsed: Vec<(Position, TokenStream, String)>,
    errors: Vec<String>,
}

pub struct Source<'a> {
    lines: Vec<&'a str>,
    trees: Vec<TokenTree>,
    syntax: Syntax,
}

impl<'a> Source<'a> {
    /// Reads a file as Rust. A file that does not parse is an error.
    pub fn lex(text: &'a str) -> Result<Self, String> {
        let stream = TokenStream::from_str(text).map_err(|e| format!("not a token stream: {e}"))?;
        let file = syn::parse_file(text).map_err(|e| {
            let at = e.span().start();
            format!("does not parse as Rust at {}:{}: {e}", at.line, at.column)
        })?;
        let lines: Vec<&str> = text.split('\n').collect();
        let mut reader = Reader {
            lines: &lines,
            syntax: Syntax::default(),
            named: 0,
        };
        reader.visit_file(&file);
        let mut syntax = reader.syntax;
        if !syntax.errors.is_empty() {
            return Err(syntax.errors.join("; "));
        }
        syntax.calls.sort_by_key(|c| c.at);
        Ok(Source {
            lines,
            trees: stream.into_iter().collect(),
            syntax,
        })
    }

    fn position(&self, at: LineColumn) -> Result<Position, String> {
        position(&self.lines, at)
    }

    /// The extent of the function whose name starts at `name`: from its
    /// first outer attribute or doc comment to the end of its body, or of its
    /// `;`. `None` when no function is written with its name there (a name a
    /// macro wrote, or something other than a function).
    pub fn fn_extent(&self, name: Position) -> Result<Option<(Position, Position)>, String> {
        Ok(self.syntax.fns.get(&name).map(|f| f.extent))
    }

    /// Where the trait's name is written in the `impl Trait for Type` header
    /// of the impl block holding the item named at `name` (the last segment
    /// of the trait's path); `None` for an inherent impl or an item in no
    /// impl block.
    pub fn impl_trait_at(&self, name: Position) -> Result<Option<Position>, String> {
        match self.impl_header_at(name)? {
            Some(header) => Ok(header.trait_name),
            None => Ok(None),
        }
    }

    /// The `impl … { }` header of the innermost impl block whose body holds
    /// the name at `name`: from `impl` to just before the body, and where the
    /// trait's name is written. `None` for an item in no impl block.
    pub fn impl_header_at(&self, name: Position) -> Result<Option<Header>, String> {
        Ok(self
            .syntax
            .impls
            .iter()
            .filter(|(_, open, close)| *open < name && name < *close)
            .max_by_key(|(_, open, _)| *open)
            .map(|(header, _, _)| *header))
    }

    /// Whether the function named at `name` takes `self` (`self`, `&self`,
    /// `&'a mut self`, `mut self`, `self: T`): such a method runs only on a
    /// value. An associated function (no `self`) runs through the type alone.
    pub fn receiver_at(&self, name: Position) -> Result<Receiver, String> {
        Ok(match self.syntax.fns.get(&name) {
            Some(f) => f.receiver,
            None => Receiver::Unread,
        })
    }

    /// Whether the type named at `at` is constructed there, not only named:
    /// a struct literal (`T { … }`), a tuple constructor (`T(…)`), a path
    /// through it (`T::new(…)`, `T::Variant`), or, for a unit struct, the
    /// type used as a value (`f(T)`). A name in a type or a pattern constructs
    /// nothing; a call's type argument or a qualified path's self type is
    /// dispatched on.
    pub fn constructs_at(&self, at: Position, shape_of_type: TypeShape) -> Result<Use, String> {
        Ok(match (self.syntax.uses.get(&at), shape_of_type) {
            (Some(PathUse::Constructs), _) => Use::Constructs,
            (Some(PathUse::TypeArgument), _) => Use::TypeArgument,
            (Some(PathUse::Names), _) => Use::Names,
            (Some(PathUse::Value), TypeShape::UnitStruct) => Use::Constructs,
            (Some(PathUse::Value), TypeShape::Other) => Use::Names,
            (None, _) => Use::NoToken,
        })
    }

    /// What the token starting at `at` is part of: an attribute (by its
    /// path, `derive` for `#[derive(…)]`), a macro invocation's name, or
    /// something else.
    pub fn what_is_at(&self, at: Position) -> Result<AtPosition, String> {
        if let Some((_, _, path)) = self
            .syntax
            .attributes
            .iter()
            .find(|(start, end, _)| *start <= at && at < *end)
        {
            return Ok(AtPosition::InAttribute(path.clone()));
        }
        if let Some(name) = self.syntax.macro_names.get(&at) {
            return Ok(AtPosition::MacroCall(name.clone()));
        }
        Ok(match self.innermost_start(&self.trees, at)? {
            Some(start) if start == at => AtPosition::Other,
            _ => AtPosition::NoToken,
        })
    }

    /// Where the innermost token holding `at` starts, if a token holds it.
    fn innermost_start(
        &self,
        trees: &[TokenTree],
        at: Position,
    ) -> Result<Option<Position>, String> {
        for tree in trees {
            let (start, end) = (
                self.position(tree.span().start())?,
                self.position(tree.span().end())?,
            );
            if at < start || end <= at {
                continue;
            }
            return match tree {
                TokenTree::Group(g) if start != at => {
                    // The closing delimiter is the group's own token.
                    let close = self.position(g.span_close().start())?;
                    if close <= at {
                        return Ok(Some(close));
                    }
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    self.innermost_start(&inner, at)
                }
                _ => Ok(Some(start)),
            };
        }
        Ok(None)
    }

    /// Whether the file declares `mod <name>;` (with any attributes or
    /// visibility), at any depth.
    pub fn declares_module(&self, name: &str) -> bool {
        self.syntax.modules.contains(name)
    }

    /// What the item written at `[start, end]` begins with: a macro
    /// invocation (`path!(…)`, `path! { … }`, with its attributes) or
    /// something else; `Absent` when no token lies inside.
    pub fn head_at(&self, start: Position, end: Position) -> Result<Head, String> {
        let first = self
            .syntax
            .nodes
            .iter()
            .filter(|n| start <= n.start && n.start < end)
            .min_by_key(|n| (n.start, std::cmp::Reverse(n.end)));
        if let Some(n) = first {
            return Ok(n.head);
        }
        Ok(match self.first_token_in(&self.trees, start, end)? {
            Some(_) => Head::Other,
            None => Head::Absent,
        })
    }

    /// Where the first token inside `[start, end)` starts, at any depth.
    fn first_token_in(
        &self,
        trees: &[TokenTree],
        start: Position,
        end: Position,
    ) -> Result<Option<Position>, String> {
        for tree in trees {
            let (from, to) = (
                self.position(tree.span().start())?,
                self.position(tree.span().end())?,
            );
            if to <= start || end <= from {
                continue;
            }
            if start <= from {
                return Ok(Some(from));
            }
            if let TokenTree::Group(g) = tree {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                if let Some(found) = self.first_token_in(&inner, start, end)? {
                    return Ok(Some(found));
                }
                // No inner token: the closing delimiter, if the extent holds it.
                let close = self.position(g.span_close().start())?;
                if start <= close && close < end {
                    return Ok(Some(close));
                }
            }
        }
        Ok(None)
    }

    /// Every name written in call position inside `[start, end]`: `name(…)`,
    /// `receiver.name(…)` and `Path::name(…)`, in order. Attributes and
    /// definitions are not calls.
    pub fn calls(&self, start: Position, end: Position) -> Result<Vec<Call>, String> {
        Ok(self
            .syntax
            .calls
            .iter()
            .filter(|c| start <= c.at && c.at <= end)
            .cloned()
            .collect())
    }

    /// The first construct this map does not read, if the file holds one:
    /// an `asm!` or `global_asm!` invocation, or a `#[link_section]`.
    pub fn unread_construct(&self) -> Result<Option<String>, String> {
        Ok(unread(&self.trees))
    }

    /// The macro invocations whose tokens this file's reading could only
    /// read token by token: where each is named, and why it parsed as nothing.
    pub fn token_read(&self) -> Vec<(Position, &str)> {
        self.syntax
            .unparsed
            .iter()
            .map(|(at, _, why)| (*at, why.as_str()))
            .collect()
    }

    /// The names of the functions this file writes, at any depth.
    pub fn functions_defined(&self) -> BTreeSet<String> {
        self.syntax.functions.clone()
    }

    /// Every name the file writes in a `use` of one of `crates`, or in a path
    /// through one of them (`crates[i]::a::b`), the crate's own name
    /// included.
    pub fn names_used_from(&self, crates: &[&str]) -> Result<BTreeSet<String>, String> {
        let mut out = BTreeSet::new();
        for (first, names) in self.syntax.use_trees.iter().chain(&self.syntax.crate_paths) {
            if crates.contains(&first.as_str()) {
                out.extend(names.iter().cloned());
            }
        }
        // Tokens that do not parse: every name, when any crate is named.
        for (_, tokens, _) in &self.syntax.unparsed {
            let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
            let names = all_identifiers(&trees);
            if crates.iter().any(|c| names.contains(*c)) {
                out.extend(names);
            }
        }
        Ok(out)
    }
}

struct Reader<'l, 'a> {
    lines: &'l [&'a str],
    syntax: Syntax,
    /// How many types, patterns or bounds the reader is inside: a path
    /// there is only named, never a value.
    named: usize,
}

impl Reader<'_, '_> {
    fn at(&mut self, at: LineColumn) -> Option<Position> {
        match position(self.lines, at) {
            Ok(p) => Some(p),
            Err(e) => {
                self.syntax.errors.push(e);
                None
            }
        }
    }

    fn extent(&mut self, span: Span) -> Option<(Position, Position)> {
        let start = self.at(span.start())?;
        let end = self.at(span.end())?;
        Some((start, end))
    }

    fn record(&mut self, ident: &syn::Ident, used: PathUse) {
        if let Some(at) = self.at(ident.span().start()) {
            self.syntax.uses.entry(at).or_insert(used);
        }
    }

    fn function(&mut self, name: &syn::Ident, sig: &syn::Signature, span: Span) {
        let Some(extent) = self.extent(span) else {
            return;
        };
        let Some(at) = self.at(name.span().start()) else {
            return;
        };
        let receiver = match sig.receiver() {
            Some(_) => Receiver::TakesSelf,
            None => Receiver::NoSelf,
        };
        self.syntax.fns.insert(at, FnRead { extent, receiver });
        self.syntax.functions.insert(name_of(name));
    }

    fn node(&mut self, span: Span, head: Head) {
        if let Some((start, end)) = self.extent(span) {
            self.syntax.nodes.push(Node { start, end, head });
        }
    }

    /// Reads a path written as a value or a callee: every segment before
    /// the last constructs (a path through the type); the last is `last`;
    /// generic arguments are dispatched on.
    fn value_path(&mut self, qself: Option<&syn::QSelf>, path: &syn::Path, last: PathUse) {
        if let Some(q) = qself {
            self.dispatched(&q.ty);
        }
        let count = path.segments.len();
        for (k, segment) in path.segments.iter().enumerate() {
            let used = if k + 1 == count {
                last
            } else {
                PathUse::Constructs
            };
            self.record(&segment.ident, used);
            self.arguments(&segment.arguments);
        }
        self.crate_path(path);
    }

    /// A type a call dispatches on: its own name is dispatched on; names
    /// inside it (its generic arguments, a reference's target) are named.
    fn dispatched(&mut self, ty: &syn::Type) {
        match ty {
            syn::Type::Path(p) if p.qself.is_none() => {
                if let Some(last) = p.path.segments.last() {
                    self.record(&last.ident, PathUse::TypeArgument);
                }
            }
            _ => {}
        }
        self.named += 1;
        self.visit_type(ty);
        self.named -= 1;
    }

    fn arguments(&mut self, arguments: &syn::PathArguments) {
        if let syn::PathArguments::AngleBracketed(a) = arguments {
            self.turbofish(a);
        }
    }

    fn turbofish(&mut self, a: &syn::AngleBracketedGenericArguments) {
        for argument in &a.args {
            match argument {
                syn::GenericArgument::Type(ty) => self.dispatched(ty),
                other => {
                    self.named += 1;
                    self.visit_generic_argument(other);
                    self.named -= 1;
                }
            }
        }
    }

    fn crate_path(&mut self, path: &syn::Path) {
        let names: Vec<String> = path.segments.iter().map(|s| name_of(&s.ident)).collect();
        if let Some(first) = names.first() {
            self.syntax.crate_paths.push((first.clone(), names.clone()));
        }
    }

    /// A macro invocation: its name, and its tokens read as items,
    /// expressions or statements, or kept as tokens that parse as nothing.
    fn invocation(&mut self, mac: &syn::Macro) {
        if let Some(last) = mac.path.segments.last() {
            if let Some(at) = self.at(last.ident.span().start()) {
                self.syntax.macro_names.insert(at, name_of(&last.ident));
            }
        }
        self.crate_path(&mac.path);
        let tokens = mac.tokens.clone();
        let as_items = match syn::parse2::<syn::File>(tokens.clone()) {
            Ok(file) => {
                self.visit_file(&file);
                return;
            }
            Err(e) => e,
        };
        let as_exprs = match syn::parse::Parser::parse2(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
            tokens.clone(),
        ) {
            Ok(exprs) => {
                for e in &exprs {
                    self.visit_expr(e);
                }
                return;
            }
            Err(e) => e,
        };
        let as_statements =
            match syn::parse::Parser::parse2(syn::Block::parse_within, tokens.clone()) {
                Ok(stmts) => {
                    for s in &stmts {
                        self.visit_stmt(s);
                    }
                    return;
                }
                Err(e) => e,
            };
        let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
        self.token_calls(&trees);
        self.syntax.functions.extend(token_functions(&trees));
        let at = match mac.path.segments.last() {
            Some(last) => self.at(last.ident.span().start()),
            None => self.at(mac.span().start()),
        };
        let Some(at) = at else {
            return;
        };
        self.syntax.unparsed.push((
            at,
            tokens,
            format!(
                "as items: {as_items}; as expressions: {as_exprs}; as statements: {as_statements}"
            ),
        ));
    }

    /// Call candidates in tokens that parse as nothing: every name followed
    /// by `(…)` (after a turbofish, if any), except a `fn` being defined and
    /// the language's own forms.
    fn token_calls(&mut self, trees: &[TokenTree]) {
        for (k, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(g) => {
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    self.token_calls(&inner);
                }
                TokenTree::Ident(id) => {
                    let name = id.to_string();
                    let arguments_at = match turbofish_end(trees, k + 1) {
                        Some(end) => end,
                        None => k + 1,
                    };
                    let called = trees.get(arguments_at).is_some_and(
                        |t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis),
                    );
                    let prev = |back: usize| k.checked_sub(back).and_then(|j| trees.get(j));
                    let defined =
                        prev(1).is_some_and(|t| matches!(t, TokenTree::Ident(i) if i == "fn"));
                    if !called || defined || KEYWORDS.contains(&name.as_str()) {
                        continue;
                    }
                    let form = match (prev(1), prev(2), prev(3)) {
                        (Some(TokenTree::Punct(p)), _, _) if p.as_char() == '.' => Form::Method,
                        (
                            Some(TokenTree::Punct(a)),
                            Some(TokenTree::Punct(b)),
                            Some(TokenTree::Ident(q)),
                        ) if a.as_char() == ':' && b.as_char() == ':' => {
                            Form::Path(Some(q.to_string()))
                        }
                        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)), _)
                            if a.as_char() == ':' && b.as_char() == ':' =>
                        {
                            Form::Path(None)
                        }
                        _ => Form::Bare,
                    };
                    if let Some(at) = self.at(id.span().start()) {
                        self.syntax.calls.push(Call { at, name, form });
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn call(&mut self, ident: &syn::Ident, form: Form) {
        let name = name_of(ident);
        if let Some(at) = self.at(ident.span().start()) {
            self.syntax.calls.push(Call { at, name, form });
        }
    }
}

impl<'ast> Visit<'ast> for Reader<'_, '_> {
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        if let Some(last) = a.path().segments.last() {
            let path = name_of(&last.ident);
            if let Some((start, end)) = self.extent(a.span()) {
                self.syntax.attributes.push((start, end, path));
            }
        }
    }

    fn visit_item(&mut self, i: &'ast syn::Item) {
        let head = match i {
            syn::Item::Macro(_) => Head::MacroCall,
            _ => Head::Other,
        };
        self.node(i.span(), head);
        syn::visit::visit_item(self, i);
    }

    fn visit_impl_item(&mut self, i: &'ast syn::ImplItem) {
        let head = match i {
            syn::ImplItem::Macro(_) => Head::MacroCall,
            _ => Head::Other,
        };
        self.node(i.span(), head);
        syn::visit::visit_impl_item(self, i);
    }

    fn visit_trait_item(&mut self, i: &'ast syn::TraitItem) {
        let head = match i {
            syn::TraitItem::Macro(_) => Head::MacroCall,
            _ => Head::Other,
        };
        self.node(i.span(), head);
        syn::visit::visit_trait_item(self, i);
    }

    fn visit_stmt_macro(&mut self, s: &'ast syn::StmtMacro) {
        self.node(s.span(), Head::MacroCall);
        syn::visit::visit_stmt_macro(self, s);
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.function(&f.sig.ident, &f.sig, f.span());
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.function(&f.sig.ident, &f.sig, f.span());
        syn::visit::visit_impl_item_fn(self, f);
    }

    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        self.function(&f.sig.ident, &f.sig, f.span());
        syn::visit::visit_trait_item_fn(self, f);
    }

    fn visit_foreign_item_fn(&mut self, f: &'ast syn::ForeignItemFn) {
        self.function(&f.sig.ident, &f.sig, f.span());
        syn::visit::visit_foreign_item_fn(self, f);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let start = self.at(i.impl_token.span.start());
        let open = self.at(i.brace_token.span.open().start());
        let close = self.at(i.brace_token.span.close().start());
        let trait_name = match &i.trait_ {
            Some((_, path, _)) => path
                .segments
                .last()
                .and_then(|s| self.at(s.ident.span().start())),
            None => None,
        };
        if let (Some(start), Some(open), Some(close)) = (start, open, close) {
            self.syntax.impls.push((
                Header {
                    start,
                    end: open,
                    trait_name,
                },
                open,
                close,
            ));
        }
        syn::visit::visit_item_impl(self, i);
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if m.content.is_none() {
            self.syntax.modules.insert(name_of(&m.ident));
        }
        syn::visit::visit_item_mod(self, m);
    }

    fn visit_use_tree(&mut self, u: &'ast syn::UseTree) {
        let mut names = Vec::new();
        use_names(u, &mut names);
        if let Some(first) = names.first() {
            self.syntax.use_trees.push((first.clone(), names.clone()));
        }
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.invocation(m);
    }

    fn visit_type(&mut self, ty: &'ast syn::Type) {
        self.named += 1;
        syn::visit::visit_type(self, ty);
        self.named -= 1;
    }

    fn visit_pat(&mut self, p: &'ast syn::Pat) {
        self.named += 1;
        syn::visit::visit_pat(self, p);
        self.named -= 1;
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        // A path in a type, a pattern, a bound or anything else not read as a
        // value: every name in it is only named.
        for segment in &path.segments {
            self.record(&segment.ident, PathUse::Names);
        }
        self.crate_path(path);
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_path(&mut self, e: &'ast syn::ExprPath) {
        for a in &e.attrs {
            self.visit_attribute(a);
        }
        // A path pattern (`Unit =>`) is an expression path in syn: inside a
        // pattern or a type it names, never makes, a value.
        if self.named > 0 {
            if let Some(q) = &e.qself {
                self.visit_type(&q.ty);
            }
            self.visit_path(&e.path);
            return;
        }
        self.value_path(e.qself.as_ref(), &e.path, PathUse::Value);
    }

    fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
        for a in &e.attrs {
            self.visit_attribute(a);
        }
        match &*e.func {
            syn::Expr::Path(p) => {
                // A tuple constructor or a function: the last segment is
                // called.
                self.value_path(p.qself.as_ref(), &p.path, PathUse::Constructs);
                if let Some(last) = p.path.segments.last() {
                    let count = p.path.segments.len();
                    let form = match (&p.qself, count) {
                        (Some(_), _) => Form::Path(None),
                        (None, 1) if p.path.leading_colon.is_none() => Form::Bare,
                        (None, _) => {
                            let before = &p.path.segments[count - 2];
                            match before.arguments {
                                syn::PathArguments::None => {
                                    Form::Path(Some(name_of(&before.ident)))
                                }
                                _ => Form::Path(None),
                            }
                        }
                    };
                    self.call(&last.ident, form);
                }
            }
            other => self.visit_expr(other),
        }
        for arg in &e.args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        for a in &e.attrs {
            self.visit_attribute(a);
        }
        self.visit_expr(&e.receiver);
        self.call(&e.method, Form::Method);
        if let Some(t) = &e.turbofish {
            self.turbofish(t);
        }
        for arg in &e.args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_struct(&mut self, e: &'ast syn::ExprStruct) {
        for a in &e.attrs {
            self.visit_attribute(a);
        }
        if let Some(q) = &e.qself {
            self.dispatched(&q.ty);
        }
        for segment in &e.path.segments {
            self.record(&segment.ident, PathUse::Constructs);
            self.arguments(&segment.arguments);
        }
        self.crate_path(&e.path);
        for field in &e.fields {
            self.visit_field_value(field);
        }
        if let Some(rest) = &e.rest {
            self.visit_expr(rest);
        }
    }
}

/// Every name a `use` tree writes, its first segment first.
fn use_names(tree: &syn::UseTree, out: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(p) => {
            out.push(name_of(&p.ident));
            use_names(&p.tree, out);
        }
        syn::UseTree::Name(n) => out.push(name_of(&n.ident)),
        syn::UseTree::Rename(r) => {
            out.push(name_of(&r.ident));
            out.push(name_of(&r.rename));
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(g) => {
            for t in &g.items {
                use_names(t, out);
            }
        }
    }
}

/// The names written after `fn` in tokens that parse as nothing.
fn token_functions(trees: &[TokenTree]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(keyword) if keyword == "fn" => {
                if let Some(TokenTree::Ident(name)) = trees.get(at + 1) {
                    out.insert(name.to_string().trim_start_matches("r#").to_string());
                }
            }
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                out.extend(token_functions(&inner));
            }
            _ => {}
        }
    }
    out
}

fn unread(trees: &[TokenTree]) -> Option<String> {
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(i)
                if (i == "asm" || i == "global_asm")
                    && matches!(trees.get(at + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!') =>
            {
                return Some(format!("`{i}!`"));
            }
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                let attribute = g.delimiter() == Delimiter::Bracket
                    && matches!(inner.first(), Some(TokenTree::Ident(i)) if i == "link_section");
                if attribute {
                    return Some("`#[link_section]`".to_string());
                }
                if let Some(found) = unread(&inner) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// A proc-macro2 position (1-based line; column counted in characters) as
/// the map's position (0-based line; column in bytes, as SCIP counts it).
pub fn position(lines: &[&str], at: LineColumn) -> Result<Position, String> {
    let line = at
        .line
        .checked_sub(1)
        .ok_or_else(|| "a token is on line 0".to_string())?;
    let text = lines
        .get(line)
        .ok_or_else(|| format!("line {} is past the end", at.line))?;
    let mut columns = text.char_indices().map(|(byte, _)| byte);
    match columns.nth(at.column) {
        Some(column) => Ok(Position { line, column }),
        None if text.chars().count() == at.column => Ok(Position {
            line,
            column: text.len(),
        }),
        None => Err(format!(
            "column {} is past the end of line {}",
            at.column, at.line
        )),
    }
}

/// Whether a type definition's text is a unit struct (`struct Name;`) or a
/// unit variant (`Name` in an enum), whose bare name is a value. Any other
/// struct, variant, enum, union, trait, alias or associated type is not. Text
/// that parses as none of them is an error.
pub fn struct_shape(text: &str) -> Result<TypeShape, String> {
    let as_item = match syn::parse_str::<syn::Item>(text) {
        Ok(syn::Item::Struct(s)) if matches!(s.fields, syn::Fields::Unit) => {
            return Ok(TypeShape::UnitStruct)
        }
        Ok(_) => return Ok(TypeShape::Other),
        Err(e) => e,
    };
    let as_variant = match syn::parse_str::<syn::Variant>(text) {
        Ok(v) if matches!(v.fields, syn::Fields::Unit) => return Ok(TypeShape::UnitStruct),
        Ok(_) => return Ok(TypeShape::Other),
        Err(e) => e,
    };
    let as_trait_item = match syn::parse_str::<syn::TraitItem>(text) {
        Ok(_) => return Ok(TypeShape::Other),
        Err(e) => e,
    };
    let as_impl_item = match syn::parse_str::<syn::ImplItem>(text) {
        Ok(_) => return Ok(TypeShape::Other),
        Err(e) => e,
    };
    let as_foreign_item = match syn::parse_str::<syn::ForeignItem>(text) {
        Ok(_) => return Ok(TypeShape::Other),
        Err(e) => e,
    };
    Err(format!(
        "{:?} parses as no type definition: as an item, {as_item}; as a variant, {as_variant}; as a trait item, {as_trait_item}; as an impl item, {as_impl_item}; as a foreign item, {as_foreign_item}",
        text.chars().take(80).collect::<String>()
    ))
}

/// The index just past a turbofish (`::<…>`) starting at `at`, if one does:
/// the `<` and `>` are matched by depth.
fn turbofish_end(trees: &[TokenTree], at: usize) -> Option<usize> {
    let starts = matches!(trees.get(at), Some(TokenTree::Punct(a)) if a.as_char() == ':')
        && matches!(trees.get(at + 1), Some(TokenTree::Punct(b)) if b.as_char() == ':')
        && matches!(trees.get(at + 2), Some(TokenTree::Punct(c)) if c.as_char() == '<');
    if !starts {
        return None;
    }
    let mut depth = 0i32;
    for (k, t) in trees.iter().enumerate().skip(at + 2) {
        match t {
            TokenTree::Punct(p) if p.as_char() == '<' => depth += 1,
            TokenTree::Punct(_) if closes_angle(trees, k) => {
                depth -= 1;
                if depth == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether the token at `k` is a `>` that closes a `<`: not the `>` of `->`
/// or `=>`.
fn closes_angle(trees: &[TokenTree], k: usize) -> bool {
    let joined_after = |c: char| {
        k.checked_sub(1)
            .and_then(|j| trees.get(j))
            .is_some_and(|t| matches!(t, TokenTree::Punct(m) if m.as_char() == c && m.spacing() == Spacing::Joint))
    };
    matches!(trees.get(k), Some(TokenTree::Punct(p)) if p.as_char() == '>')
        && !joined_after('-')
        && !joined_after('=')
}

fn all_identifiers(trees: &[TokenTree]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for tree in trees {
        match tree {
            TokenTree::Ident(i) => {
                out.insert(i.to_string());
            }
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                out.extend(all_identifiers(&inner));
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: usize, column: usize) -> Position {
        Position { line, column }
    }

    #[test]
    fn a_method_under_an_attribute_macro_gets_its_own_extent() -> Result<(), String> {
        // The index reported the whole impl block for both methods; the
        // tokens give each its own text.
        let text = "#[async_trait]\nimpl R for X {\n    /// Reads.\n    async fn query(&self) -> u8 { 1 }\n\n    #[inline]\n    pub(crate) async fn invoke(&self) -> u8 { 2 }\n}\n";
        let source = Source::lex(text)?;
        let query = source.fn_extent(at(3, 13))?;
        assert_eq!(query, Some((at(2, 4), at(3, 37))));
        let invoke = source.fn_extent(at(6, 24))?;
        assert_eq!(invoke, Some((at(5, 4), at(6, 49))));
        Ok(())
    }

    #[test]
    fn a_macro_invocation_is_told_from_an_item() -> Result<(), String> {
        let text = "/// Ids.\n#[allow_x]\ncrate::define_id!(DeviceId);\nstruct S;\n";
        let source = Source::lex(text)?;
        assert_eq!(source.head_at(at(0, 0), at(2, 27))?, Head::MacroCall);
        assert_eq!(source.head_at(at(3, 0), at(3, 9))?, Head::Other);
        Ok(())
    }

    #[test]
    fn the_trait_of_an_impl_is_read_from_its_header() -> Result<(), String> {
        let text = "fn install() {\n    struct Boot;\n    #[async_trait]\n    impl crate::bridge::Router for Boot {\n        async fn query(&self) {}\n    }\n}\nimpl<T: Clone> Show<T> for Wrap<T> { fn show(&self) {} }\nimpl Wrap<u8> { fn plain(&self) {} }\n";
        let source = Source::lex(text)?;
        // `query` is in an impl nested inside a function body.
        assert_eq!(source.impl_trait_at(at(4, 17))?, Some(at(3, 24)));
        // Generic arguments are skipped: the trait's own name, not `T`.
        assert_eq!(source.impl_trait_at(at(7, 42))?, Some(at(7, 15)));
        // An inherent impl names no trait.
        assert_eq!(source.impl_trait_at(at(8, 20))?, None);
        Ok(())
    }

    #[test]
    fn a_type_is_constructed_only_where_a_value_is_made() -> Result<(), String> {
        let text = "fn f(x: A) -> B {\n    let a = A { n: 1 };\n    let b = B::new();\n    install(Arc::new(U));\n    let v: Vec<A> = g::<A>();\n    h(&A)\n}\n";
        let source = Source::lex(text)?;
        // Type positions: a parameter, a return type, generic arguments.
        assert_eq!(
            source.constructs_at(at(0, 8), TypeShape::UnitStruct)?,
            Use::Names
        );
        assert_eq!(
            source.constructs_at(at(0, 14), TypeShape::UnitStruct)?,
            Use::Names
        );
        assert_eq!(
            source.constructs_at(at(4, 15), TypeShape::UnitStruct)?,
            Use::Names
        );
        // A literal, a path call, a unit value.
        assert_eq!(
            source.constructs_at(at(1, 12), TypeShape::Other)?,
            Use::Constructs
        );
        assert_eq!(
            source.constructs_at(at(2, 12), TypeShape::Other)?,
            Use::Constructs
        );
        assert_eq!(
            source.constructs_at(at(3, 21), TypeShape::UnitStruct)?,
            Use::Constructs
        );
        // The same unit value, when the type is not a unit struct, names it.
        assert_eq!(
            source.constructs_at(at(3, 21), TypeShape::Other)?,
            Use::Names
        );
        // In `g::<A>()` the call dispatches on A: a type argument.
        assert_eq!(
            source.constructs_at(at(4, 24), TypeShape::Other)?,
            Use::TypeArgument
        );
        Ok(())
    }

    #[test]
    fn a_qualified_path_dispatches_on_its_self_type() -> Result<(), String> {
        let text = "fn f() { <Built as Example>::static_fn(); fold::<A, Named>(); let v: Vec<Never> = x(); }\n";
        let source = Source::lex(text)?;
        assert_eq!(
            source.constructs_at(at(0, 10), TypeShape::Other)?,
            Use::TypeArgument
        );
        assert_eq!(
            source.constructs_at(at(0, 52), TypeShape::Other)?,
            Use::TypeArgument
        );
        assert_eq!(
            source.constructs_at(at(0, 73), TypeShape::Other)?,
            Use::Names
        );
        Ok(())
    }

    #[test]
    fn arrows_close_no_angle_bracket() -> Result<(), String> {
        // `->` inside a turbofish: the call is still a call, and a type
        // after the arrow's argument is still the call's type argument.
        let text = "fn f() { g::<fn() -> u8, Unit>(); }\n";
        let source = Source::lex(text)?;
        assert_eq!(
            source.constructs_at(at(0, 25), TypeShape::UnitStruct)?,
            Use::TypeArgument
        );
        let calls = source.calls(at(0, 0), at(1, 0))?;
        let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["g"]);
        Ok(())
    }

    #[test]
    fn const_arguments_end_no_header_and_no_argument_list() -> Result<(), String> {
        // A brace inside `<…>` is a const argument, not a body.
        let text = "fn f() -> Array<{ 1 }> {\n    g();\n}\nimpl Tr<{ 2 }> for Ty {\n    fn m(&self) {}\n}\nfn h() { k::<{ 3 }, Unit>(); }\n";
        let source = Source::lex(text)?;
        assert_eq!(source.fn_extent(at(0, 3))?, Some((at(0, 0), at(2, 1))));
        let header = source.impl_header_at(at(4, 7))?.ok_or("no impl header")?;
        assert_eq!(header.trait_name, Some(at(3, 5)));
        assert_eq!(
            source.constructs_at(at(6, 20), TypeShape::UnitStruct)?,
            Use::TypeArgument
        );
        Ok(())
    }

    #[test]
    fn macros_in_headers_and_const_arguments_are_parsed_not_scanned() -> Result<(), String> {
        let text = "fn f() -> wrap! { u8 } {\n    g();\n}\nimpl Tr for wrap! { Ty } {\n    fn m(&self) {}\n}\nfn h() { k::<{ 1 + 1 }, Unit>(); }\n";
        let source = Source::lex(text)?;
        // The body is the one after the return type's macro.
        assert_eq!(source.fn_extent(at(0, 3))?, Some((at(0, 0), at(2, 1))));
        assert_eq!(source.calls(at(0, 0), at(2, 1))?.len(), 1);
        let header = source.impl_header_at(at(4, 7))?.ok_or("no impl header")?;
        assert_eq!(header.trait_name, Some(at(3, 5)));
        assert_eq!(
            source.constructs_at(at(6, 24), TypeShape::UnitStruct)?,
            Use::TypeArgument
        );
        Ok(())
    }

    #[test]
    fn definitions_patterns_and_absolute_macros_are_read_as_what_they_are() -> Result<(), String> {
        let text = "struct Tuple(u8);\nenum E { V(u8) }\n::outer::made!(Id);\nfn f(x: E) -> u8 {\n    match x { crate::Unit => 1, Unit => 2, _ => 0 }\n}\n";
        let source = Source::lex(text)?;
        // A tuple struct or variant being defined is no call.
        assert_eq!(source.calls(at(0, 0), at(6, 0))?, Vec::new());
        // An absolute path to a macro is a macro invocation.
        assert_eq!(source.head_at(at(2, 0), at(2, 19))?, Head::MacroCall);
        // A path pattern names a unit struct; it makes no value. A bare name
        // in a pattern is a binding to syn: no path, so no evidence either.
        assert_eq!(
            source.constructs_at(at(4, 21), TypeShape::UnitStruct)?,
            Use::Names
        );
        assert_eq!(
            source.constructs_at(at(4, 31), TypeShape::UnitStruct)?,
            Use::NoToken
        );
        Ok(())
    }

    #[test]
    fn names_after_a_type_path_s_generic_arguments_are_read() -> Result<(), String> {
        let source = Source::lex("fn f(x: dsm::a::B<T>::C) {}\n")?;
        let names = source.names_used_from(&["dsm"])?;
        for name in ["dsm", "a", "B", "C"] {
            assert!(names.contains(name), "{name} in {names:?}");
        }
        Ok(())
    }

    #[test]
    fn raw_identifiers_are_read_as_their_names() -> Result<(), String> {
        let source = Source::lex(
            "use r#dsm_sdk::r#type::Thing;\nmod r#type;\nfn f() { r#dsm::r#match::go(); }\n",
        )?;
        let names = source.names_used_from(&["dsm_sdk", "dsm"])?;
        for name in ["dsm_sdk", "type", "Thing", "dsm", "match", "go"] {
            assert!(names.contains(name), "{name} in {names:?}");
        }
        assert!(source.declares_module("type"));
        Ok(())
    }

    #[test]
    fn a_position_inside_an_attribute_is_a_byte_column() -> Result<(), String> {
        // The map's positions count bytes on every side: `É` is two.
        let text = "const É: u8 = 1; #[derive(Clone)] struct S;\n";
        let source = Source::lex(text)?;
        let byte = text.find("Clone").ok_or("no Clone")?;
        assert_eq!(byte, 27);
        assert_eq!(
            source.what_is_at(at(0, byte))?,
            AtPosition::InAttribute("derive".to_string())
        );
        Ok(())
    }

    #[test]
    fn a_closing_delimiter_is_a_token() -> Result<(), String> {
        let text = "fn f() {\n    g();\n}\n";
        let source = Source::lex(text)?;
        assert_eq!(source.what_is_at(at(2, 0))?, AtPosition::Other);
        assert_eq!(source.head_at(at(2, 0), at(2, 1))?, Head::Other);
        // Whitespace inside a group is no token.
        assert_eq!(source.what_is_at(at(1, 1))?, AtPosition::NoToken);
        Ok(())
    }

    #[test]
    fn a_constructor_the_index_left_unresolved_is_still_a_call() -> Result<(), String> {
        // `Some(…)` and `Box::new(…)` are calls like any other; the index
        // resolving them is what keeps them out of the unresolved set.
        let source = Source::lex("fn f() { let a = Some(1); let b = Box::new(2); }\n")?;
        let names: Vec<String> = source
            .calls(at(0, 0), at(1, 0))?
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, vec!["Some", "new"]);
        Ok(())
    }

    #[test]
    fn inner_attributes_hold_no_calls() -> Result<(), String> {
        let text = "#![cfg_attr(docsrs, feature(doc_cfg))]\nfn f() { g(); }\n";
        let source = Source::lex(text)?;
        let calls = source.calls(at(0, 0), at(2, 0))?;
        let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["g"]);
        assert_eq!(
            source.what_is_at(at(0, 3))?,
            AtPosition::InAttribute("cfg_attr".to_string())
        );
        Ok(())
    }

    #[test]
    fn a_receiver_is_read_from_the_first_parameter() -> Result<(), String> {
        let text = "impl T {\n    fn a(&self) {}\n    fn b(&'x mut self, n: u8) {}\n    fn c(n: u8) {}\n    fn d(self: Box<Self>) {}\n}\n";
        let source = Source::lex(text)?;
        assert_eq!(source.receiver_at(at(1, 7))?, Receiver::TakesSelf);
        assert_eq!(source.receiver_at(at(2, 7))?, Receiver::TakesSelf);
        assert_eq!(source.receiver_at(at(3, 7))?, Receiver::NoSelf);
        assert_eq!(source.receiver_at(at(4, 7))?, Receiver::TakesSelf);
        Ok(())
    }

    #[test]
    fn functions_are_found_at_any_depth() -> Result<(), String> {
        let lexed = Source::lex(
            "#[no_mangle] pub extern \"system\" fn Java_a_B_c() {}\nmod m { fn r#inner() { fn nested() {} } }\nconst F: fn(u8) -> u8 = |x| x; // fn not_code\nwrap! { fn in_macro() {} }\n",
        )?;
        let names: Vec<String> = lexed.functions_defined().into_iter().collect();
        assert_eq!(names, vec!["Java_a_B_c", "in_macro", "inner", "nested"]);
        Ok(())
    }

    #[test]
    fn unit_structs_are_read_from_tokens() -> Result<(), String> {
        assert_eq!(
            struct_shape("/// A marker.\n#[derive(Debug)]\npub(crate) struct Unit;")?,
            TypeShape::UnitStruct
        );
        assert_eq!(
            struct_shape("struct Marker<T: Fn() -> u8>;")?,
            TypeShape::UnitStruct
        );
        assert_eq!(struct_shape("struct Tuple(u8);")?, TypeShape::Other);
        assert_eq!(
            struct_shape("pub struct Fields { a: u8 }")?,
            TypeShape::Other
        );
        assert_eq!(struct_shape("enum E { A }")?, TypeShape::Other);
        // Enum variants: a unit variant is a value.
        assert_eq!(struct_shape("/// Doc.\nConsider")?, TypeShape::UnitStruct);
        assert_eq!(struct_shape("Pair(u8, u8)")?, TypeShape::Other);
        assert_eq!(struct_shape("Named { a: u8 }")?, TypeShape::Other);
        // An associated type with no default.
        assert_eq!(struct_shape("type Output;")?, TypeShape::Other);
        Ok(())
    }

    #[test]
    fn a_name_that_is_not_a_fn_item_has_no_fn_extent() -> Result<(), String> {
        let source = Source::lex("struct Query;\nconst query: u8 = 1;\n")?;
        assert_eq!(source.fn_extent(at(0, 7))?, None);
        assert_eq!(source.fn_extent(at(1, 6))?, None);
        Ok(())
    }

    #[test]
    fn columns_are_utf8_bytes() -> Result<(), String> {
        // `é` is two bytes: the index counts bytes, the lexer characters.
        let source = Source::lex("fn a() { let s = \"é\"; b(s) }\n")?;
        let calls = source.calls(at(0, 0), at(0, 30))?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "b");
        assert_eq!(calls[0].at, at(0, 23));
        Ok(())
    }

    #[test]
    fn calls_are_read_with_their_form() -> Result<(), String> {
        let text = "fn f() { g(1); x.h(2); Type::k(3); if (a) {} m!(n()); #[cfg(p(q))] r(); }\n";
        let source = Source::lex(text)?;
        let calls = source.calls(at(0, 0), at(0, 80))?;
        let got: Vec<(String, Form)> = calls.into_iter().map(|c| (c.name, c.form)).collect();
        assert_eq!(
            got,
            vec![
                ("g".to_string(), Form::Bare),
                ("h".to_string(), Form::Method),
                ("k".to_string(), Form::Path(Some("Type".to_string()))),
                ("n".to_string(), Form::Bare),
                ("r".to_string(), Form::Bare),
            ]
        );
        Ok(())
    }

    #[test]
    fn names_used_from_a_crate_come_from_its_uses_and_paths() -> Result<(), String> {
        let text = "use dsm_sdk::bridge::{install, Store as S};\nuse std::sync::Arc;\nfn f() { dsm::crypto::verify(); other::thing(); }\n";
        let source = Source::lex(text)?;
        let names = source.names_used_from(&["dsm_sdk", "dsm"])?;
        let expected: BTreeSet<String> = [
            "dsm_sdk", "bridge", "install", "Store", "S", "dsm", "crypto", "verify",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(names, expected);
        Ok(())
    }
}
