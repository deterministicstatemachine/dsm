// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading rust-analyzer SCIP symbols: `rust-analyzer cargo <package> <version> <descriptors>`.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Callable,
    Type,
    Term,
    Macro,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Callable => "callable",
            Kind::Type => "type",
            Kind::Term => "term",
            Kind::Macro => "macro",
        }
    }
}

/// The named item a symbol denotes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub package: String,
    pub modules: Vec<String>,
    pub kind: Kind,
    pub name: String,
    /// The type a method or field belongs to: the `Self` of its impl block, or
    /// the type or trait it is declared in. Empty for free items.
    pub container: String,
    /// The trait an impl block implements. Empty for inherent impls and free items.
    pub trait_name: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Descriptor {
    Namespace(String),
    Type(String),
    Term(String),
    Method(String),
    Macro(String),
    TypeParameter(String),
    Parameter(String),
    Meta(String),
}

/// The item `symbol` names, or `None` for local symbols and for descriptors
/// that name no item (modules, parameters, type parameters).
pub fn item(symbol: &str) -> Result<Option<Item>, String> {
    if symbol.starts_with("local ") {
        return Ok(None);
    }
    let mut parts = symbol.splitn(5, ' ');
    let (scheme, manager, package, version, descriptors) = match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(s), Some(m), Some(p), Some(v), Some(d)) => (s, m, p, v, d),
        _ => return Err(format!("symbol {symbol:?} does not have five parts")),
    };
    if scheme.is_empty() || manager.is_empty() || version.is_empty() {
        return Err(format!(
            "symbol {symbol:?} has an empty scheme, manager or version"
        ));
    }
    let list = descriptors_of(descriptors).map_err(|e| format!("symbol {symbol:?}: {e}"))?;
    let mut modules = Vec::new();
    let mut last_type = String::new();
    let mut impl_self = String::new();
    let mut impl_trait = String::new();
    let mut in_impl = 0u8;
    let count = list.len();
    for (at, descriptor) in list.iter().enumerate() {
        let last = at + 1 == count;
        match descriptor {
            Descriptor::Namespace(name) => {
                modules.push(name.clone());
                in_impl = 0;
            }
            Descriptor::Type(name) if name == "impl" && !last => {
                in_impl = 1;
                impl_self.clear();
                impl_trait.clear();
            }
            Descriptor::TypeParameter(name) if in_impl == 1 => {
                impl_self = name.clone();
                in_impl = 2;
            }
            Descriptor::TypeParameter(name) if in_impl == 2 => {
                impl_trait = name.clone();
                in_impl = 3;
            }
            Descriptor::Type(name) => {
                if last {
                    return Ok(Some(Item {
                        package: package.to_string(),
                        modules,
                        kind: Kind::Type,
                        name: name.clone(),
                        container: container_of(&last_type, &impl_self, in_impl),
                        trait_name: String::new(),
                    }));
                }
                last_type = name.clone();
                in_impl = 0;
                impl_self.clear();
                impl_trait.clear();
            }
            Descriptor::Method(name) | Descriptor::Term(name) | Descriptor::Macro(name) if last => {
                let kind = match descriptor {
                    Descriptor::Method(_) => Kind::Callable,
                    Descriptor::Term(_) => Kind::Term,
                    _ => Kind::Macro,
                };
                return Ok(Some(Item {
                    package: package.to_string(),
                    modules,
                    kind,
                    name: name.clone(),
                    container: container_of(&last_type, &impl_self, in_impl),
                    trait_name: if in_impl >= 2 {
                        impl_trait
                    } else {
                        String::new()
                    },
                }));
            }
            Descriptor::Method(name) | Descriptor::Term(name) | Descriptor::Macro(name) => {
                last_type = name.clone();
                in_impl = 0;
            }
            Descriptor::TypeParameter(_) | Descriptor::Parameter(_) | Descriptor::Meta(_) => {
                if last {
                    return Ok(None);
                }
            }
        }
    }
    Ok(None)
}

fn container_of(last_type: &str, impl_self: &str, in_impl: u8) -> String {
    if in_impl >= 2 {
        impl_self.to_string()
    } else {
        last_type.to_string()
    }
}

/// The bare type name: generic arguments and the path dropped, so
/// `` `Foo<'_>` `` and `` `pb::Foo` `` both name `Foo`.
pub fn base_name(name: &str) -> &str {
    let unparameterised = match name.find(['<', ' ', '(']) {
        Some(end) => &name[..end],
        None => name,
    };
    match unparameterised.rfind("::") {
        Some(at) => &unparameterised[at + 2..],
        None => unparameterised,
    }
}

fn descriptors_of(text: &str) -> Result<Vec<Descriptor>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < chars.len() {
        match chars[at] {
            '[' => {
                at += 1;
                let name = read_name(&chars, &mut at)?;
                expect(&chars, &mut at, ']')?;
                out.push(Descriptor::TypeParameter(name));
            }
            '(' => {
                at += 1;
                let name = read_name(&chars, &mut at)?;
                expect(&chars, &mut at, ')')?;
                out.push(Descriptor::Parameter(name));
            }
            _ => {
                let name = read_name(&chars, &mut at)?;
                let suffix = match chars.get(at) {
                    Some(c) => *c,
                    None => return Err(format!("descriptor {name:?} has no suffix")),
                };
                at += 1;
                match suffix {
                    '/' => out.push(Descriptor::Namespace(name)),
                    '#' => out.push(Descriptor::Type(name)),
                    '.' => out.push(Descriptor::Term(name)),
                    ':' => out.push(Descriptor::Meta(name)),
                    '!' => out.push(Descriptor::Macro(name)),
                    '(' => {
                        while at < chars.len() && chars[at] != ')' {
                            at += 1;
                        }
                        expect(&chars, &mut at, ')')?;
                        expect(&chars, &mut at, '.')?;
                        out.push(Descriptor::Method(name));
                    }
                    other => return Err(format!("descriptor {name:?} has suffix {other:?}")),
                }
            }
        }
    }
    Ok(out)
}

fn expect(chars: &[char], at: &mut usize, want: char) -> Result<(), String> {
    match chars.get(*at) {
        Some(c) if *c == want => {
            *at += 1;
            Ok(())
        }
        found => Err(format!("expected {want:?} at {at}, found {found:?}")),
    }
}

fn read_name(chars: &[char], at: &mut usize) -> Result<String, String> {
    let mut out = String::new();
    if chars.get(*at) == Some(&'`') {
        *at += 1;
        loop {
            match chars.get(*at) {
                None => return Err("a backticked name is not closed".to_string()),
                Some('`') if chars.get(*at + 1) == Some(&'`') => {
                    out.push('`');
                    *at += 2;
                }
                Some('`') => {
                    *at += 1;
                    return Ok(out);
                }
                Some(c) => {
                    out.push(*c);
                    *at += 1;
                }
            }
        }
    }
    while let Some(c) = chars.get(*at) {
        if c.is_alphanumeric() || "_+-$".contains(*c) {
            out.push(*c);
            *at += 1;
        } else {
            break;
        }
    }
    if out.is_empty() {
        return Err(format!("expected a name at {at}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKG: &str = "rust-analyzer cargo dsm_sdk 0.1.0-beta.3 ";

    fn parsed(descriptors: &str) -> Result<Item, String> {
        item(&format!("{PKG}{descriptors}"))?.ok_or_else(|| format!("{descriptors} names no item"))
    }

    #[test]
    fn a_free_function() -> Result<(), String> {
        let it = parsed("jni/ble_events/Java_com_dsm_wallet_bridge_UnifiedNativeApi_x().")?;
        assert_eq!(it.kind, Kind::Callable);
        assert_eq!(it.name, "Java_com_dsm_wallet_bridge_UnifiedNativeApi_x");
        assert_eq!(it.modules, vec!["jni", "ble_events"]);
        assert!(it.container.is_empty());
        assert!(it.trait_name.is_empty());
        Ok(())
    }

    #[test]
    fn an_inherent_method_belongs_to_its_self_type() -> Result<(), String> {
        let it = parsed("types/device_state/impl#[DeviceState]advance().")?;
        assert_eq!(
            (it.kind, it.name.as_str(), it.container.as_str()),
            (Kind::Callable, "advance", "DeviceState")
        );
        assert!(it.trait_name.is_empty());
        Ok(())
    }

    #[test]
    fn a_trait_impl_method_names_its_trait() -> Result<(), String> {
        let it = parsed("init/impl#[MinimalBootstrapRouter][AppRouter]query().")?;
        assert_eq!(it.container, "MinimalBootstrapRouter");
        assert_eq!(it.trait_name, "AppRouter");
        let shown = parsed("tla_trace_replay/impl#[`TlaValueDisplay<'_>`][Display]fmt().")?;
        assert_eq!(base_name(&shown.container), "TlaValueDisplay");
        let generated = parsed("wire/impl#[`pb::Hash32`][`From<[u8; 32]>`]from().")?;
        assert_eq!(
            (
                base_name(&generated.container),
                base_name(&generated.trait_name)
            ),
            ("Hash32", "From")
        );
        assert_eq!(shown.trait_name, "Display");
        Ok(())
    }

    #[test]
    fn a_trait_method_declaration_belongs_to_the_trait() -> Result<(), String> {
        let it = parsed("bridge/AppRouter#query().")?;
        assert_eq!(
            (it.name.as_str(), it.container.as_str()),
            ("query", "AppRouter")
        );
        Ok(())
    }

    #[test]
    fn fields_types_and_tests() -> Result<(), String> {
        let field = parsed("handlers/app_router_impl/AppRouterImpl#wallet.")?;
        assert_eq!(
            (field.kind, field.container.as_str()),
            (Kind::Term, "AppRouterImpl")
        );
        assert_eq!(parsed("bridge/AppRouter#")?.kind, Kind::Type);
        let test = parsed("route_chain/tests/only_links_of_one_chain_count_toward_final().")?;
        assert_eq!(test.modules, vec!["route_chain", "tests"]);
        Ok(())
    }

    #[test]
    fn modules_parameters_and_locals_name_no_item() -> Result<(), String> {
        assert_eq!(item(&format!("{PKG}handlers/app_router_impl/"))?, None);
        assert_eq!(item(&format!("{PKG}sdk/f().(amount)"))?, None);
        assert_eq!(item("local 42")?, None);
        Ok(())
    }

    #[test]
    fn malformed_symbols_are_errors() {
        assert!(matches!(item("rust-analyzer cargo dsm"), Err(e) if e.contains("five parts")));
        assert!(matches!(item(&format!("{PKG}a`")), Err(e) if e.contains("has suffix '`'")));
        assert!(matches!(item(&format!("{PKG}`open")), Err(e) if e.contains("not closed")));
    }
}
