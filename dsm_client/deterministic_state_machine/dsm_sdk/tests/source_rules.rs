// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rules about what production code does, read from Core's and the SDK's
//! sources with syn. Each holds a property no single run can show — a door
//! nobody else may open, an input nobody may read, an order no path may break
//! — and fails, naming the place, when a change breaks it.

mod source_calls;

use source_calls::{
    calls_in_order, cfg_gated, core_src, events, parse, production_fn, production_fns, rust_files,
    sdk_source, Event,
};
use syn::punctuated::Punctuated;
use syn::{Fields, ImplItem, Item, Token, UseTree, Visibility};

// ── MR-SOFI-0337: the faucet asks before it signs ──────────────────────────

/// SoFi Amendment S11: at the reserve's exhaustion a faucet claim is refused
/// before anything is signed or written. A real reserve reaches exhaustion
/// only after every unit of ERA's committed genesis supply is released, so no
/// run reaches it through the claim flow; Core's `faucet_claim_admissible`
/// decides the refusal and its own tests drive a reserve to zero. This holds
/// the claim flow to asking it before it signs or freezes a release.
///
/// MUTATION CONTROL: deleting the `faucet_claim_admissible` call from
/// `claim_era_faucet`, or moving it after the release is signed, turns this
/// red.
#[test]
fn a_faucet_claim_asks_whether_the_reserve_is_exhausted_before_it_signs_or_freezes() {
    let flow = sdk_source("sdk/faucet_claim_flow.rs");
    let calls = calls_in_order(&production_fn(&flow, "claim_era_faucet"));
    let first = |name: &str| calls.iter().position(|c| c == name);
    let Some(asked) = first("faucet_claim_admissible") else {
        panic!("claim_era_faucet never asks whether the reserve is exhausted: {calls:?}");
    };
    for written in ["sign_release", "freeze_release"] {
        let Some(at) = first(written) else {
            panic!("claim_era_faucet calls {written}: {calls:?}");
        };
        assert!(
            asked < at,
            "claim_era_faucet calls {written} before it asks whether the reserve is \
             exhausted: {calls:?}"
        );
    }
}

// ── MR-SOFI-0281: one function prepares every SoFi transition ──────────────

/// Every file that produces a SoFi, escrow, computed or outcome transition.
const PRODUCERS: &[&str] = &[
    "sdk/sofi_advance.rs",
    "sdk/sofi_flow.rs",
    "sdk/sofi_exercise.rs",
    "sdk/sofi_publish.rs",
    "sdk/sofi_register.rs",
    "sdk/sofi_relay.rs",
    "sdk/sofi_sdk.rs",
    "sdk/escrow_flow.rs",
    "sdk/computed_flow.rs",
    "sdk/outcome_programs.rs",
    "sdk/apply_outcome.rs",
    "sdk/seed_vault.rs",
    "handlers/sofi_routes.rs",
    "handlers/escrow_routes.rs",
];

/// The lower-level advances, all methods: what `admitted_advance` is built
/// from.
const LOWER_LEVEL: &[&str] = &[
    ".advance",
    ".establish_relationship",
    ".cross_offline_boundary",
    ".open_offline_account",
    ".with_resolved_position",
    ".with_pending_economic_admission",
    ".set_device_head",
    ".execute_on_relationship_guarded",
];

/// The preparing function, a method of `CoreSDK`, and the self-loop path that
/// runs it.
const PREPARING: &[&str] = &[".admitted_advance", "admitted_self_loop_operation"];

/// SoFi §46: one function prepares every transition, and no SoFi producer
/// calls a lower-level advance.
///
/// MUTATION CONTROL: a SoFi producer that advances its head directly — say
/// `core.device_head()?.advance(..)` in `sofi_advance.rs` in place of
/// `admitted_advance` — turns this red, naming the file and function.
#[test]
fn every_sofi_producer_advances_only_through_the_one_preparing_function() {
    let mut reaches_preparing = Vec::new();
    for rel in PRODUCERS {
        for (name, block) in production_fns(&sdk_source(rel)) {
            let calls = calls_in_order(&block);
            for call in &calls {
                assert!(
                    !LOWER_LEVEL.contains(&call.as_str()),
                    "{rel}: {name} calls the lower-level advance {call}; SoFi transitions are \
                     prepared only by admitted_advance"
                );
            }
            if calls.iter().any(|c| PREPARING.contains(&c.as_str())) {
                reaches_preparing.push(format!("{rel}: {name}"));
            }
        }
    }
    assert!(
        !reaches_preparing.is_empty(),
        "no SoFi producer reaches admitted_advance: the producer list no longer names the \
         files that advance"
    );
}

// ── MR-DSM-0218, MR-SOFI-0056: no clock, height or duration in SoFi ────────

/// Path segments that read a clock or measure time.
const CLOCK_PATHS: &[&str] = &[
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "Duration",
    "Utc",
    "Local",
    "chrono",
    "sleep",
];

/// Methods that measure time.
const CLOCK_METHODS: &[&str] = &["elapsed", "duration_since"];

/// Names an input that is a time, a height or a duration would carry.
const TIME_NAMES: &[&str] = &[
    "timestamp",
    "time",
    "deadline",
    "expiry",
    "expires",
    "expires_at",
    "timeout",
    "duration",
    "valid_until",
    "valid_after",
    "not_before",
    "not_after",
    "block_height",
    "btc_height",
    "chain_height",
];

fn use_idents(tree: &UseTree, out: &mut Vec<String>) {
    match tree {
        UseTree::Path(p) => {
            out.push(p.ident.to_string());
            use_idents(&p.tree, out);
        }
        UseTree::Name(n) => out.push(n.ident.to_string()),
        UseTree::Rename(r) => out.push(r.ident.to_string()),
        UseTree::Group(g) => {
            for item in &g.items {
                use_idents(item, out);
            }
        }
        UseTree::Glob(..) => {}
    }
}

/// Every production `use` path segment, parameter name and field name in
/// `items`, inline modules included.
fn declared_names(items: &[Item], uses: &mut Vec<String>, names: &mut Vec<String>) {
    let params = |sig: &syn::Signature, names: &mut Vec<String>| {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(typed) = input {
                if let syn::Pat::Ident(ident) = &*typed.pat {
                    names.push(ident.ident.to_string());
                }
            }
        }
    };
    for item in items {
        match item {
            Item::Use(u) if !cfg_gated(&u.attrs) => use_idents(&u.tree, uses),
            Item::Fn(f) if !cfg_gated(&f.attrs) => params(&f.sig, names),
            Item::Impl(i) if !cfg_gated(&i.attrs) => {
                for inner in &i.items {
                    if let ImplItem::Fn(f) = inner {
                        if !cfg_gated(&f.attrs) {
                            params(&f.sig, names);
                        }
                    }
                }
            }
            Item::Struct(s) if !cfg_gated(&s.attrs) => {
                if let Fields::Named(fields) = &s.fields {
                    for field in &fields.named {
                        if let Some(ident) = &field.ident {
                            names.push(ident.to_string());
                        }
                    }
                }
            }
            Item::Mod(m) if !cfg_gated(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    declared_names(inner, uses, names);
                }
            }
            _ => {}
        }
    }
}

/// SoFi §8 and Amendment A13: no timestamp, height or duration appears in any
/// SoFi validity rule, and Core's SoFi safety assumes none of the liveness
/// conditions. No production function under Core's `sofi` reads a clock or
/// measures time, imports a time module, or takes or stores an input named as
/// a time, a height or a duration.
///
/// MUTATION CONTROL: a `std::time::Instant::now()` in a SoFi predicate, a
/// `use std::time::Duration;`, or a parameter `deadline: u64` turns this red.
#[test]
fn no_sofi_validity_rule_reads_a_clock_a_height_or_a_duration() {
    let files = rust_files(&core_src().join("sofi"));
    assert!(!files.is_empty(), "Core's sofi module is where it was");
    for path in files {
        let file = parse(&path);
        for (name, block) in production_fns(&file) {
            for event in events(&block) {
                match event {
                    Event::Call(segments) => assert!(
                        !segments.iter().any(|s| CLOCK_PATHS.contains(&s.as_str())),
                        "{}: {name} calls {} — a clock or a measure of time",
                        path.display(),
                        segments.join("::")
                    ),
                    Event::Method(method) => assert!(
                        !CLOCK_METHODS.contains(&method.as_str()),
                        "{}: {name} calls .{method}() — a measure of time",
                        path.display()
                    ),
                    Event::Field { .. } | Event::Construct(..) => {}
                }
            }
        }
        let (mut uses, mut names) = (Vec::new(), Vec::new());
        declared_names(&file.items, &mut uses, &mut names);
        for used in &uses {
            assert!(
                used != "time" && !CLOCK_PATHS.contains(&used.as_str()),
                "{} imports {used}: a time module or type",
                path.display()
            );
        }
        for named in &names {
            assert!(
                !TIME_NAMES.contains(&named.as_str()),
                "{} names an input or field {named}: a time, height or duration",
                path.display()
            );
        }
    }
}

// ── MR-SOFI-0274, MR-SOFI-0018: evidence is never defaulted ────────────────

/// The `#[derive(..)]` paths `attrs` apply unconditionally, and those applied
/// under `cfg_attr(cond, derive(..))` with their condition.
fn derives(attrs: &[syn::Attribute]) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("derive") {
            let paths =
                match attr.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated) {
                    Ok(paths) => paths,
                    Err(e) => panic!("a derive list parses: {e}"),
                };
            for path in paths {
                if let Some(last) = path.segments.last() {
                    out.push((None, last.ident.to_string()));
                }
            }
        } else if attr.path().is_ident("cfg_attr") {
            let parsed = attr.parse_args_with(|input: syn::parse::ParseStream<'_>| {
                let condition: syn::Meta = input.parse()?;
                input.parse::<Token![,]>()?;
                let applied = Punctuated::<syn::Meta, Token![,]>::parse_terminated(input)?;
                Ok((condition, applied))
            });
            let (condition, applied) = match parsed {
                Ok(parsed) => parsed,
                Err(e) => panic!("a cfg_attr parses: {e}"),
            };
            let condition = match &condition {
                syn::Meta::Path(path) => path.segments.last().map(|s| s.ident.to_string()),
                _ => Some("a condition that is not a single name".to_string()),
            };
            for meta in applied {
                if let syn::Meta::List(list) = meta {
                    if list.path.is_ident("derive") {
                        let paths = match list
                            .parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
                        {
                            Ok(paths) => paths,
                            Err(e) => panic!("a derive list parses: {e}"),
                        };
                        for path in paths {
                            if let Some(last) = path.segments.last() {
                                out.push((condition.clone(), last.ident.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn struct_named<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemStruct {
    let found = file.items.iter().find_map(|item| match item {
        Item::Struct(s) if s.ident == name => Some(s),
        _ => None,
    });
    let Some(found) = found else {
        panic!("struct {name} is defined where it was");
    };
    found
}

/// SoFi §37, Gate G2: `Evidence` derives `Default` only under test, and no
/// production code anywhere calls `Evidence::default()`; `ConformanceEvidence`
/// has no `Default` at all, and no `impl Default` gives either one. Evidence
/// is acquired, never filled in.
///
/// MUTATION CONTROL: `#[derive(Default)]` on `Evidence` outside `cfg_attr(test,
/// ..)`, an `impl Default for ConformanceEvidence`, or an `Evidence::default()`
/// in a production function turns this red.
#[test]
fn evidence_is_never_defaulted_outside_tests() {
    let validation = parse(&core_src().join("sofi/validation.rs"));
    for (condition, derived) in derives(&struct_named(&validation, "Evidence").attrs) {
        if derived == "Default" {
            assert_eq!(
                condition.as_deref(),
                Some("test"),
                "Evidence derives Default outside test"
            );
        }
    }
    let conformance = parse(&core_src().join("sofi/conformance.rs"));
    assert!(
        !derives(&struct_named(&conformance, "ConformanceEvidence").attrs)
            .iter()
            .any(|(_, derived)| derived == "Default"),
        "ConformanceEvidence derives Default"
    );

    let defaulted = ["Evidence", "ConformanceEvidence"];
    let sdk_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for path in rust_files(&core_src())
        .into_iter()
        .chain(rust_files(&sdk_src))
    {
        let file = parse(&path);
        for item in &file.items {
            if let Item::Impl(i) = item {
                let implements_default = i
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path.segments.last())
                    .is_some_and(|s| s.ident == "Default");
                let for_evidence = matches!(
                    &*i.self_ty,
                    syn::Type::Path(p) if p
                        .path
                        .segments
                        .last()
                        .is_some_and(|s| defaulted.contains(&s.ident.to_string().as_str()))
                );
                assert!(
                    cfg_gated(&i.attrs) || !(implements_default && for_evidence),
                    "{} implements Default for evidence",
                    path.display()
                );
            }
        }
        for (name, block) in production_fns(&file) {
            for event in events(&block) {
                if let Event::Call(segments) = event {
                    let called = segments.join("::");
                    assert!(
                        !defaulted
                            .iter()
                            .any(|ty| called.ends_with(&format!("{ty}::default"))),
                        "{}: {name} calls {called}",
                        path.display()
                    );
                }
            }
        }
    }
}

// ── MR-SOFI-0020: every piece of evidence is consumed ──────────────────────

fn field_names(item: &syn::ItemStruct) -> Vec<String> {
    match &item.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .filter_map(|f| f.ident.as_ref().map(ToString::to_string))
            .collect(),
        Fields::Unnamed(..) | Fields::Unit => Vec::new(),
    }
}

/// SoFi §2: every module on the path is used, and every piece of evidence is
/// consumed by the constructor. Each field of `Evidence` is read — from an
/// evidence binding, or by one of its own methods — in `validation.rs`, the
/// predicate `RouteValidation` runs, and each field of
/// `ConformanceEvidence` by one of `conformance.rs`. (That every public SoFi
/// function is called is Gate G1, `ci/sofi_reachability.py`.)
///
/// MUTATION CONTROL: adding a field to `Evidence` that no check reads turns
/// this red.
#[test]
fn every_evidence_item_is_consumed_by_its_predicate() {
    for (file, ty) in [
        ("sofi/validation.rs", "Evidence"),
        ("sofi/conformance.rs", "ConformanceEvidence"),
    ] {
        let source = parse(&core_src().join(file));
        let mut read: Vec<String> = production_fns(&source)
            .iter()
            .flat_map(|(_, block)| events(block))
            .filter_map(|event| match event {
                Event::Field {
                    base: Some(base),
                    name,
                } if base.contains("evidence") => Some(name),
                _ => None,
            })
            .collect();
        // And through `self`, in the evidence type's own methods.
        for item in &source.items {
            let Item::Impl(imp) = item else {
                continue;
            };
            let of_evidence = matches!(
                &*imp.self_ty,
                syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == ty)
            );
            if cfg_gated(&imp.attrs) || !of_evidence {
                continue;
            }
            for inner in &imp.items {
                let ImplItem::Fn(method) = inner else {
                    continue;
                };
                read.extend(
                    events(&method.block)
                        .into_iter()
                        .filter_map(|event| match event {
                            Event::Field {
                                base: Some(base),
                                name,
                            } if base == "self" => Some(name),
                            _ => None,
                        }),
                );
            }
        }
        for field in field_names(struct_named(&source, ty)) {
            assert!(
                read.contains(&field),
                "{ty}.{field} is carried and never read by {file}"
            );
        }
    }
}

// ── MR-SOFI-0001, MR-SOFI-0017, MR-SOFI-0023: only Core makes a state ──────

/// The states Core's transitions produce and its verifiers establish, by the
/// file that defines each.
const CORE_STATES: &[(&str, &str)] = &[
    ("types/device_state.rs", "DeviceState"),
    ("types/device_state.rs", "RealizedHead"),
    ("economic/lineage.rs", "ValidatedEconomicRoot"),
    ("economic/register.rs", "RegisteredEconomicRoot"),
    ("economic/provenance.rs", "FundedCredit"),
    ("economic/native_reserve.rs", "NativeReserveState"),
    ("sofi/validation.rs", "VaultPostState"),
    ("sofi/lineage.rs", "AcceptedVaultGenesis"),
    ("sofi/exercise.rs", "RecognizedExercise"),
    ("sofi/facts.rs", "EstablishedFacts"),
    ("sofi/facts.rs", "GroundFacts"),
    ("sofi/resolution.rs", "VaultChain"),
    ("shared_lineage/mod.rs", "EstablishedSharedHead"),
    ("shared_lineage/mod.rs", "GenerationChain"),
];

/// SoFi §2: the constructor is the only door. Nothing outside Core creates,
/// repairs, completes or adjusts a state, so no state Core makes has a public
/// field another layer could write into a value of its own or a copy it
/// adjusts: each is built by Core's transitions and read through Core's
/// accessors. (The device head's door is `one_door_for_device_heads`.)
///
/// MUTATION CONTROL: making any field of these public — the reserve state's
/// `remaining_supply`, as it was — turns this red.
#[test]
fn no_state_core_makes_has_a_field_another_layer_can_set() {
    for (file, ty) in CORE_STATES {
        let source = parse(&core_src().join(file));
        let state = struct_named(&source, ty);
        for field in state.fields.iter() {
            assert!(
                !matches!(field.vis, Visibility::Public(_)),
                "{ty}.{} in {file} is public: another layer could make or adjust the state",
                field
                    .ident
                    .as_ref()
                    .map_or_else(|| "(unnamed)".to_string(), ToString::to_string)
            );
        }
    }
}

// ── MR-STOR-0020: Core's storage facts come from route chains ──────────────

/// Storage spec §13: Core derives exactly three storage facts from raw reads
/// — `LeaderHeld` and `Final` from a cell's route chains, `Stored` from three
/// exact copies — and uses nothing else from storage. The raw reads of a
/// seat are interpreted in `route_chain.rs` alone: no other Core production
/// function reads a cell's seats, and no other Core file names a seat's read
/// or its arrival log.
///
/// MUTATION CONTROL: a verifier in `sofi/` that reads `evidence.seats[0]`
/// to decide something turns this red.
#[test]
fn core_reads_a_cells_seats_only_where_it_evaluates_route_chains() {
    let interpreter = core_src().join("route_chain.rs");
    for path in rust_files(&core_src()) {
        if path == interpreter {
            continue;
        }
        let file = parse(&path);
        for (name, block) in production_fns(&file) {
            for event in events(&block) {
                if let Event::Field { name: field, .. } = &event {
                    assert!(
                        field != "seats",
                        "{}: {name} reads a cell's seats",
                        path.display()
                    );
                }
            }
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => panic!("read {}: {e}", path.display()),
        };
        let code: String = text
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");
        for raw in ["SeatEvidence", "HeldLog"] {
            assert!(
                !code.contains(raw),
                "{} names {raw}: a seat's raw read",
                path.display()
            );
        }
    }
}

// ── MR-SOFI-0254, 0260, 0261, 0272: the producer stops where Core says ─────

/// Where each of `names` is first called in `calls`, in order; panics naming
/// the first missing one.
fn first_calls(calls: &[String], names: &[&str], what: &str) -> Vec<usize> {
    names
        .iter()
        .map(|name| match calls.iter().position(|c| c == name) {
            Some(at) => at,
            None => panic!("{what} never calls {name}: {calls:?}"),
        })
        .collect()
}

/// SoFi §31 and rule T5: producers assemble and publish; Core decides. A
/// precommit is publishable only as a `PrecommitDraft`, whose fields are the
/// producer's own and which `check_draft` alone makes, only once Core's
/// `validate` answers Valid — Invalid and Incomplete both stop it. And the
/// producer acquires the evidence, has Core check the draft, and only then
/// signs, freezes and publishes; nothing of a draft that is not Valid, or
/// whose evidence is not in hand, is signed, frozen, published, exercised or
/// advanced.
///
/// MUTATION CONTROL: deleting the `check_draft` call from
/// `prepare_fulfillment`, moving it after the signature or the freeze, or a
/// second place that builds a `PrecommitDraft`, turns this red.
#[test]
fn a_producer_signs_freezes_and_publishes_only_a_draft_core_found_valid() {
    let sdk = sdk_source("sdk/sofi_sdk.rs");
    let draft = struct_named(&sdk, "PrecommitDraft");
    assert!(
        draft
            .fields
            .iter()
            .all(|field| !matches!(field.vis, Visibility::Public(_))),
        "PrecommitDraft has a public field: a draft could be built without Core's check"
    );
    for (name, block) in production_fns(&sdk) {
        let builds = events(&block)
            .into_iter()
            .any(|event| matches!(&event, Event::Construct(path) if path.last().is_some_and(|s| s == "PrecommitDraft")));
        assert!(
            !builds || name == "check_draft",
            "sofi_sdk.rs: {name} builds a PrecommitDraft; only check_draft may"
        );
    }
    let check = calls_in_order(&production_fn(&sdk, "check_draft"));
    first_calls(&check, &["validate"], "check_draft");

    let flow = sdk_source("sdk/sofi_flow.rs");
    let prepare = calls_in_order(&production_fn(&flow, "prepare_fulfillment"));
    let at = first_calls(
        &prepare,
        &[
            ".acquire_evidence",
            "check_draft",
            "sign",
            "freeze_prepared",
            "publish_prepared",
        ],
        "prepare_fulfillment",
    );
    assert!(
        at.windows(2).all(|pair| pair[0] < pair[1]),
        "prepare_fulfillment acquires, checks, signs, freezes and publishes out of order: \
         {prepare:?}"
    );
}

/// SoFi §31 stages 4 to 6, MR-SOFI-0261: `P`, its preimage and its closure
/// are published with the durability required — each read back Stored —
/// before the transition that exercises them.
///
/// MUTATION CONTROL: dropping `require_stored` from `publish_prepared`, or
/// fulfilling before publishing in `finish_prepared`, turns this red.
#[test]
fn a_producer_exercises_only_what_it_has_read_back_stored() {
    let flow = sdk_source("sdk/sofi_flow.rs");
    first_calls(
        &calls_in_order(&production_fn(&flow, "publish_prepared")),
        &["publish_all", "require_stored"],
        "publish_prepared",
    );
    let finish = calls_in_order(&production_fn(&flow, "finish_prepared"));
    let at = first_calls(&finish, &["publish_prepared", "fulfill"], "finish_prepared");
    assert!(
        at[0] < at[1],
        "finish_prepared fulfills before it publishes: {finish:?}"
    );
}

// ── MR-SOFI-0273, MR-SOFI-0268: Gate G1 and rule T1 ────────────────────────

/// Gate G1 (SoFi §37) and rule T1 (§35): every public SoFi function, method
/// and item has a production caller or user, as the compiler front end
/// resolves it (`ci/sofi_reachability.py`, rust-analyzer's index of the
/// workspace; production safety checks run it on the whole tree). This runs
/// its negative control: on a workspace whose public SoFi method has no
/// caller and whose public SoFi type nothing uses, beside a called method of
/// the same name on another type, the gate fails naming both; once
/// production code calls the method and uses the type, it passes.
///
/// MUTATION CONTROL: the gate counting a reference by name instead of by its
/// resolved symbol, or skipping methods or items, turns this red.
#[test]
fn the_reachability_gate_names_an_uncalled_public_sofi_method_and_an_unused_type() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let control = match std::process::Command::new("bash")
        .arg("ci/sofi_reachability_negative_control.sh")
        .current_dir(&root)
        .output()
    {
        Ok(output) => output,
        Err(e) => panic!("the negative control did not run: {e}"),
    };
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&control.stdout),
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(control.status.success(), "{said}");
    assert!(said.contains("G1 negative control:"), "{said}");
}
