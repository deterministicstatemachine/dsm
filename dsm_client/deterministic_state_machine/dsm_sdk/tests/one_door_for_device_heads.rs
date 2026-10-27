// SPDX-License-Identifier: MIT OR Apache-2.0
//! MR-DSM-0243/0244: the realization predicate is the only way a device head
//! comes into existence, and no path creates one while skipping a step of it.
//!
//! Core holds that by type. `StateMachine` holds and installs only a
//! `RealizedHead`; its field is private; Core's genesis constructor, `restore`
//! (a head this device persisted, checked against its stored root) and the
//! transitions on a realized head are the only producers; and `DeviceState`'s
//! own state-producing methods are not public, so the SDK cannot build a head
//! and install it. This reads Core's source and fails when any of that is
//! reopened.

use std::path::PathBuf;
use syn::{FnArg, ImplItem, Item, ReturnType, Type, Visibility};

fn core_source(rel: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../dsm/src")
        .join(rel);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    match syn::parse_file(&text) {
        Ok(file) => file,
        Err(e) => panic!("parse {}: {e}", path.display()),
    }
}

fn type_names(ty: &Type) -> String {
    quote_type(ty)
}

fn quote_type(ty: &Type) -> String {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| {
                let args = match &s.arguments {
                    syn::PathArguments::AngleBracketed(a) => a
                        .args
                        .iter()
                        .map(|g| match g {
                            syn::GenericArgument::Type(t) => quote_type(t),
                            _ => String::new(),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => String::new(),
                };
                format!("{}<{}>", s.ident, args)
            })
            .collect::<Vec<_>>()
            .join("::"),
        Type::Reference(r) => quote_type(&r.elem),
        Type::Tuple(t) => t.elems.iter().map(quote_type).collect::<Vec<_>>().join(","),
        _ => String::new(),
    }
}

fn returns(sig: &syn::Signature) -> String {
    match &sig.output {
        ReturnType::Default => String::new(),
        ReturnType::Type(_, ty) => type_names(ty),
    }
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn is_crate_only(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Restricted(r) if r.path.is_ident("crate"))
}

/// Inherent impls of `name` that are compiled in production (no `cfg` attribute).
fn production_impls<'a>(file: &'a syn::File, name: &str) -> Vec<&'a syn::ItemImpl> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(i)
                if i.trait_.is_none()
                    && type_names(&i.self_ty).starts_with(name)
                    && !i.attrs.iter().any(|a| a.path().is_ident("cfg")) =>
            {
                Some(i)
            }
            _ => None,
        })
        .collect()
}

fn methods(impls: &[&syn::ItemImpl]) -> Vec<syn::ImplItemFn> {
    impls
        .iter()
        .flat_map(|i| i.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(f) => Some(f.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_device_head_is_installed_only_as_a_head_core_realized() {
    let device_state = core_source("types/device_state.rs");

    // The wrapper's field is private: nothing outside Core can make one.
    let Some(realized) = device_state.items.iter().find_map(|item| match item {
        Item::Struct(s) if s.ident == "RealizedHead" => Some(s),
        _ => None,
    }) else {
        panic!("RealizedHead is defined in device_state.rs");
    };
    for field in realized.fields.iter() {
        assert!(
            matches!(field.vis, Visibility::Inherited),
            "RealizedHead's field must be private: a public field lets any caller wrap any state"
        );
    }

    // Its one wrapping constructor is Core's own.
    let realized_methods = methods(&production_impls(&device_state, "RealizedHead"));
    let Some(of) = realized_methods.iter().find(|f| f.sig.ident == "of") else {
        panic!("RealizedHead::of");
    };
    assert!(
        is_crate_only(&of.vis),
        "RealizedHead::of must stay pub(crate): it wraps any DeviceState"
    );

    // DeviceState's own state-producing methods are Core's, never the SDK's:
    // each takes or yields a plain state, so a public one would be a door.
    let state_methods = methods(&production_impls(&device_state, "DeviceState"));
    for name in [
        "advance",
        "establish_relationship",
        "with_pending_economic_admission",
        "with_resolved_position",
        "open_offline_account",
        "cross_offline_boundary",
    ] {
        let Some(f) = state_methods.iter().find(|f| f.sig.ident == name) else {
            panic!("DeviceState::{name} exists");
        };
        assert!(
            !is_public(&f.vis),
            "DeviceState::{name} is public: a caller could build a head without Core's door"
        );
    }

    // The only public producers of a realized head are the genesis head,
    // restore and the transitions on a realized head.
    for f in state_methods.iter().filter(|f| is_public(&f.vis)) {
        let out = returns(&f.sig);
        if out.contains("RealizedHead") {
            assert!(
                ["genesis_head", "restore"].contains(&f.sig.ident.to_string().as_str()),
                "DeviceState::{} returns a RealizedHead; only genesis_head and restore may",
                f.sig.ident
            );
        }
    }
    for f in realized_methods.iter().filter(|f| is_public(&f.vis)) {
        let takes_realized_self = matches!(f.sig.inputs.first(), Some(FnArg::Receiver(_)));
        if returns(&f.sig).contains("RealizedHead") || returns(&f.sig).contains("Outcome") {
            assert!(
                takes_realized_self,
                "RealizedHead::{} produces a head without starting from a realized one",
                f.sig.ident
            );
        }
    }
}

#[test]
fn the_state_machine_holds_and_installs_only_a_realized_head() {
    let state_machine = core_source("core/state_machine/mod.rs");
    let Some(machine) = state_machine.items.iter().find_map(|item| match item {
        Item::Struct(s) if s.ident == "StateMachine" => Some(s),
        _ => None,
    }) else {
        panic!("StateMachine is defined");
    };
    let Some(held) = machine
        .fields
        .iter()
        .find(|f| f.ident.as_ref().is_some_and(|i| i == "device_state"))
    else {
        panic!("StateMachine::device_state");
    };
    assert!(
        type_names(&held.ty).contains("RealizedHead"),
        "StateMachine must hold a RealizedHead, not a plain DeviceState: {}",
        type_names(&held.ty)
    );

    let impls = production_impls(&state_machine, "StateMachine");
    let Some(set) = methods(&impls)
        .into_iter()
        .find(|f| f.sig.ident == "set_device_head")
    else {
        panic!("StateMachine::set_device_head");
    };
    let Some(param) = set.sig.inputs.iter().find_map(|arg| match arg {
        FnArg::Typed(t) => Some(type_names(&t.ty)),
        FnArg::Receiver(_) => None,
    }) else {
        panic!("set_device_head takes the head");
    };
    assert!(
        param.contains("RealizedHead") && !param.contains("DeviceState<"),
        "set_device_head must take a RealizedHead: {param}"
    );
}
