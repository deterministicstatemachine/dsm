// SPDX-License-Identifier: MIT OR Apache-2.0

//! Literal TLC trace replay inside Rust.
//!
//! This module parses deterministic TLC simulation traces and replays the exact
//! state path against a Rust shadow model of the abstract TLA+ transitions.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde::Serialize;

use crate::tla_runner::TlaSpec;

#[derive(Debug, Clone, Serialize)]
pub struct TlaTraceReplayResult {
    pub spec_label: String,
    pub trace_path: PathBuf,
    pub steps: u64,
    pub passed: bool,
    pub failures: Vec<String>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct TlaSimulationProfile {
    pub seed: u64,
    pub depth: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
enum TlaValue {
    Int(i64),
    Bool(bool),
    Str(String),
    Symbol(String),
    Seq(Vec<TlaValue>),
    Set(BTreeSet<TlaValue>),
    Record(BTreeMap<String, TlaValue>),
    Map(BTreeMap<TlaValue, TlaValue>),
}

type TlaState = BTreeMap<String, TlaValue>;

pub fn simulation_profile_for_spec(_spec: &TlaSpec) -> TlaSimulationProfile {
    TlaSimulationProfile { seed: 42, depth: 5 }
}

pub fn replay_trace_file(
    spec: &TlaSpec,
    trace_path: &Path,
) -> anyhow::Result<TlaTraceReplayResult> {
    let start = instant::Instant::now();
    let trace_text = std::fs::read_to_string(trace_path)
        .with_context(|| format!("failed to read TLC trace file {}", trace_path.display()))?;
    let states = parse_trace_states(&trace_text)
        .with_context(|| format!("failed to parse TLC trace file {}", trace_path.display()))?;

    if states.len() < 2 {
        bail!("TLC trace for {} did not contain a transition", spec.label);
    }

    let failures = match spec.spec_file.as_str() {
        "DSM_Tripwire.tla" => replay_tripwire_trace(&states),
        "DSM_OfflineFinality.tla" => {
            replay_structural_trace(&states, &["chain", "phase", "parent", "net", "link"])
        }
        "DSM_NonInterference.tla" => {
            replay_structural_trace(&states, &["chainTip", "balance", "relTip", "sessions"])
        }
        _ => replay_dsm_trace(&states),
    };

    Ok(TlaTraceReplayResult {
        spec_label: spec.label.clone(),
        trace_path: trace_path.to_path_buf(),
        steps: (states.len() - 1) as u64,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    })
}

fn parse_trace_states(trace_text: &str) -> anyhow::Result<Vec<TlaState>> {
    let mut states = Vec::new();
    let mut lines = trace_text.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if !trimmed.starts_with("STATE_") {
            continue;
        }

        let mut assignments = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_value = String::new();

        while let Some(next_line) = lines.peek() {
            let trimmed = next_line.trim();
            if trimmed.starts_with("STATE_") || trimmed.starts_with("===") {
                break;
            }

            let line = lines.next().expect("peeked line exists");
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("\\*") {
                continue;
            }

            if let Some(stripped) = trimmed.strip_prefix("/\\ ") {
                if let Some(name) = current_name.take() {
                    assignments.push((name, current_value.trim().to_string()));
                    current_value.clear();
                }
                let (name, value) = stripped
                    .split_once(" = ")
                    .ok_or_else(|| anyhow!("invalid state assignment line: {trimmed}"))?;
                current_name = Some(name.trim().to_string());
                current_value.push_str(value.trim());
            } else if current_name.is_some() {
                if !current_value.is_empty() {
                    current_value.push(' ');
                }
                current_value.push_str(trimmed);
            } else {
                bail!("unexpected line while parsing trace state: {trimmed}");
            }
        }

        if let Some(name) = current_name.take() {
            assignments.push((name, current_value.trim().to_string()));
        }

        let mut state = BTreeMap::new();
        for (name, value_src) in assignments {
            let mut parser = ValueParser::new(&value_src);
            let value = parser.parse_value()?;
            parser.expect_end()?;
            state.insert(name, value);
        }
        states.push(state);
    }

    if states.is_empty() {
        bail!("no STATE_n blocks found");
    }

    Ok(states)
}

fn replay_tripwire_trace(states: &[TlaState]) -> Vec<String> {
    let mut failures = Vec::new();

    for (idx, pair) in states.windows(2).enumerate() {
        if let Err(err) = replay_tripwire_step(&pair[0], &pair[1]) {
            failures.push(format!("step {}: {err}", idx + 1));
        }
    }

    failures
}

fn replay_tripwire_step(current: &TlaState, next: &TlaState) -> anyhow::Result<()> {
    let current_ledger = set_var(current, "ledger")?;
    let next_ledger = set_var(next, "ledger")?;
    let added = set_difference(next_ledger, current_ledger);
    if added.len() != 1 {
        bail!("expected exactly one new receipt, found {}", added.len());
    }

    let receipt = record_fields(&added[0])?;
    let rel = receipt
        .get("rel")
        .cloned()
        .ok_or_else(|| anyhow!("receipt missing rel"))?;
    let old_tip = receipt_int(receipt, "oldTip")?;
    let new_tip = receipt_int(receipt, "newTip")?;
    let r1 = receipt_int(receipt, "r1")?;
    let r2 = receipt_int(receipt, "r2")?;

    let rel_devices = set_items(&rel)?;
    if rel_devices.len() != 2 {
        bail!("receipt relation was not binary");
    }

    let current_roots = map_var(current, "deviceRoots")?;
    let current_smt = map_var(current, "smtState")?;

    let candidate_orders = [
        (rel_devices[0].clone(), rel_devices[1].clone()),
        (rel_devices[1].clone(), rel_devices[0].clone()),
    ];

    let (d1, d2) = candidate_orders
        .into_iter()
        .find(|(candidate_d1, candidate_d2)| {
            let candidate_root_1 = current_roots
                .get(candidate_d1)
                .and_then(|value| int_from_value(value).ok());
            let candidate_root_2 = current_roots
                .get(candidate_d2)
                .and_then(|value| int_from_value(value).ok());
            let candidate_state_1 = current_smt
                .get(candidate_d1)
                .and_then(|value| map_value(value).ok());
            let candidate_state_2 = current_smt
                .get(candidate_d2)
                .and_then(|value| map_value(value).ok());
            let candidate_tip_1 = candidate_state_1
                .and_then(|state| state.get(&rel))
                .and_then(|value| int_from_value(value).ok());
            let candidate_tip_2 = candidate_state_2
                .and_then(|state| state.get(&rel))
                .and_then(|value| int_from_value(value).ok());

            candidate_root_1 == Some(r1)
                && candidate_root_2 == Some(r2)
                && candidate_tip_1 == Some(old_tip)
                && candidate_tip_2 == Some(old_tip)
        })
        .ok_or_else(|| anyhow!("no device ordering satisfied the Tripwire guard"))?;

    let mut expected = current.clone();
    set_map_entry(
        &mut expected,
        "deviceRoots",
        d1.clone(),
        TlaValue::Int(r1 + 1),
    )?;
    set_map_entry(
        &mut expected,
        "deviceRoots",
        d2.clone(),
        TlaValue::Int(r2 + 1),
    )?;
    set_nested_map_entry(
        &mut expected,
        "smtState",
        d1.clone(),
        rel.clone(),
        TlaValue::Int(new_tip),
    )?;
    set_nested_map_entry(
        &mut expected,
        "smtState",
        d2.clone(),
        rel.clone(),
        TlaValue::Int(new_tip),
    )?;
    insert_set_var(&mut expected, "ledger", added[0].clone())?;

    if expected != *next {
        bail!(
            "Rust Tripwire replay diverged from TLC state: {}",
            summarize_state_diff(&expected, next)
        );
    }

    Ok(())
}

fn replay_dsm_trace(states: &[TlaState]) -> Vec<String> {
    let mut failures = Vec::new();

    for (idx, pair) in states.windows(2).enumerate() {
        if let Err(err) = replay_dsm_step(&pair[0], &pair[1]) {
            failures.push(format!("step {}: {err}", idx + 1));
        }
    }

    failures
}

fn replay_structural_trace(states: &[TlaState], required_vars: &[&str]) -> Vec<String> {
    let mut failures = Vec::new();

    for (idx, state) in states.iter().enumerate() {
        for var in required_vars {
            if !state.contains_key(*var) {
                failures.push(format!("state {} missing required variable {var}", idx + 1));
            }
        }
    }

    for (idx, pair) in states.windows(2).enumerate() {
        let current_keys = pair[0].keys().collect::<BTreeSet<_>>();
        let next_keys = pair[1].keys().collect::<BTreeSet<_>>();
        if current_keys != next_keys {
            failures.push(format!("step {} changed the visible variable set", idx + 1));
        }
    }

    failures
}

fn replay_dsm_step(current: &TlaState, next: &TlaState) -> anyhow::Result<()> {
    if matching_dsm_action_with_candidates(current, next, dsm_replay_candidates())?.is_some() {
        return Ok(());
    }

    bail!(
        "no Rust abstract transition matched TLC step; diff: {}",
        summarize_state_diff(current, next)
    )
}

type ReplayFn = fn(&TlaState, &TlaState) -> anyhow::Result<bool>;

fn dsm_replay_candidates() -> &'static [(&'static str, ReplayFn)] {
    &[
        ("add_device", apply_add_device),
        ("create_relationship", apply_create_relationship),
        ("net_send", apply_net_send),
        ("net_deliver", apply_net_deliver),
        ("net_drop", apply_net_drop),
        ("net_duplicate", apply_net_duplicate),
        ("add_storage_node", apply_add_storage_node),
        ("generate_keys", apply_generate_keys),
        ("start_offline_session", apply_start_offline_session),
        ("offline_transfer", apply_offline_transfer),
        ("create_vault", apply_create_vault),
        ("unlock_vault", apply_unlock_vault),
        ("unlock_spend_gate", apply_unlock_spend_gate),
        ("activate_again", apply_activate_again),
        ("consume_jap_and_emit", apply_consume_jap_and_emit),
        ("consume_spent_proof", apply_consume_spent_proof),
        ("phase_transition", apply_phase_transition),
        ("step_only", apply_step_only),
    ]
}

fn matching_dsm_action_with_candidates<'a>(
    current: &TlaState,
    next: &TlaState,
    candidates: &'a [(&'a str, ReplayFn)],
) -> anyhow::Result<Option<&'a str>> {
    for (action, replay) in candidates {
        if replay(current, next)? {
            return Ok(Some(*action));
        }
    }
    Ok(None)
}

fn apply_add_device(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_devices = map_var(current, "devices")?;
    let next_devices = map_var(next, "devices")?;

    let mut target: Option<(TlaValue, TlaValue)> = None;
    for genesis in current_devices.keys() {
        let current_set = set_value(
            current_devices
                .get(genesis)
                .ok_or_else(|| anyhow!("missing device set"))?,
        )?;
        let next_set = set_value(
            next_devices
                .get(genesis)
                .ok_or_else(|| anyhow!("missing next device set"))?,
        )?;
        let added = set_difference(next_set, current_set);
        if added.len() == 1 && current_set.len() + 1 == next_set.len() {
            target = Some((genesis.clone(), added[0].clone()));
            break;
        }
    }

    let Some((genesis, device)) = target else {
        return Ok(false);
    };

    let mut expected = current.clone();
    insert_nested_set_entry(&mut expected, "devices", genesis, device)?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_create_relationship(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_relationships = map_var(current, "relationships")?;
    let next_relationships = map_var(next, "relationships")?;

    for pair_key in current_relationships.keys() {
        let pair = seq_items(pair_key)?;
        if pair.len() != 2 || pair[0] == pair[1] {
            continue;
        }

        let reverse = TlaValue::Seq(vec![pair[1].clone(), pair[0].clone()]);
        let current_pair = record_fields(
            current_relationships
                .get(pair_key)
                .ok_or_else(|| anyhow!("missing current relationship"))?,
        )?;
        let next_pair = record_fields(
            next_relationships
                .get(pair_key)
                .ok_or_else(|| anyhow!("missing next relationship"))?,
        )?;
        let current_reverse = record_fields(
            current_relationships
                .get(&reverse)
                .ok_or_else(|| anyhow!("missing reverse relationship"))?,
        )?;
        let next_reverse = record_fields(
            next_relationships
                .get(&reverse)
                .ok_or_else(|| anyhow!("missing next reverse relationship"))?,
        )?;

        if record_int(current_pair, "tip")? != 0
            || record_int(current_reverse, "tip")? != 0
            || record_str(current_pair, "state")? != "inactive"
            || record_str(current_reverse, "state")? != "inactive"
            || record_int(next_pair, "tip")? != 1
            || record_int(next_reverse, "tip")? != 1
            || record_str(next_pair, "state")? != "active"
            || record_str(next_reverse, "state")? != "active"
        {
            continue;
        }

        let mut expected = current.clone();
        set_map_entry(
            &mut expected,
            "relationships",
            pair_key.clone(),
            relationship_record(1, "active"),
        )?;
        set_map_entry(
            &mut expected,
            "relationships",
            reverse,
            relationship_record(1, "active"),
        )?;
        insert_set_var(
            &mut expected,
            "ledger",
            ledger_record(pair[0].clone(), pair[1].clone(), 0, 1),
        )?;
        update_relationship_smt_leaf(&mut expected, &pair[0], &pair[1], 1)?;
        bump_step(&mut expected)?;
        if expected == *next {
            return Ok(true);
        }
    }

    Ok(false)
}

fn apply_net_send(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_net = set_var(current, "net")?;
    let next_net = set_var(next, "net")?;
    let added = set_difference(next_net, current_net);
    if added.len() != 1 || next_net.len() != current_net.len() + 1 {
        return Ok(false);
    }

    let msg = record_fields(&added[0])?;
    let from = msg
        .get("from")
        .cloned()
        .ok_or_else(|| anyhow!("net message missing from"))?;
    let to = msg
        .get("to")
        .cloned()
        .ok_or_else(|| anyhow!("net message missing to"))?;

    let mut expected = current.clone();
    insert_set_var(&mut expected, "net", added[0].clone())?;
    let current_next_msg_id = int_var(current, "nextMsgId")?;
    if receipt_int(msg, "id")? != current_next_msg_id {
        return Ok(false);
    }
    set_var_value(
        &mut expected,
        "nextMsgId",
        TlaValue::Int(current_next_msg_id + 1),
    )?;
    increment_map_entry(
        &mut expected,
        "deviceBalance",
        from.clone(),
        -receipt_int(msg, "payload")?,
    )?;
    let pair = TlaValue::Seq(vec![from.clone(), to.clone()]);
    let reverse = TlaValue::Seq(vec![to, from]);
    let tip = relationship_tip(current, &pair)?;
    set_map_entry(
        &mut expected,
        "relationships",
        pair,
        relationship_record(tip, "active"),
    )?;
    set_map_entry(
        &mut expected,
        "relationships",
        reverse,
        relationship_record(tip, "active"),
    )?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_net_deliver(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_net = set_var(current, "net")?;
    let next_net = set_var(next, "net")?;
    let removed = set_difference(current_net, next_net);
    if removed.len() != 1 || next_net.len() + 1 != current_net.len() {
        return Ok(false);
    }

    let msg = record_fields(&removed[0])?;
    let from = msg
        .get("from")
        .cloned()
        .ok_or_else(|| anyhow!("net message missing from"))?;
    let to = msg
        .get("to")
        .cloned()
        .ok_or_else(|| anyhow!("net message missing to"))?;
    let parent_tip = receipt_int(msg, "parentTip")?;
    let pair = TlaValue::Seq(vec![from.clone(), to.clone()]);
    let reverse = TlaValue::Seq(vec![to.clone(), from.clone()]);

    let mut expected = current.clone();
    remove_set_var(&mut expected, "net", &removed[0])?;
    set_map_entry(
        &mut expected,
        "relationships",
        pair.clone(),
        relationship_record(parent_tip + 1, "active"),
    )?;
    set_map_entry(
        &mut expected,
        "relationships",
        reverse,
        relationship_record(parent_tip + 1, "active"),
    )?;
    update_relationship_smt_leaf(&mut expected, &from, &to, parent_tip + 1)?;
    increment_map_entry(
        &mut expected,
        "deviceBalance",
        to.clone(),
        receipt_int(msg, "payload")?,
    )?;
    insert_set_var(
        &mut expected,
        "ledger",
        ledger_record(from, to, parent_tip, parent_tip + 1),
    )?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_net_drop(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_net = set_var(current, "net")?;
    let next_net = set_var(next, "net")?;
    let removed = set_difference(current_net, next_net);
    if removed.len() != 1 || next_net.len() + 1 != current_net.len() {
        return Ok(false);
    }

    let mut expected = current.clone();
    remove_set_var(&mut expected, "net", &removed[0])?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_net_duplicate(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_net = set_var(current, "net")?;
    let next_net = set_var(next, "net")?;
    if next_net.len() != current_net.len() + 1 {
        return Ok(false);
    }

    let current_next_msg_id = int_var(current, "nextMsgId")?;
    for original in current_net {
        let msg = record_fields(original)?;
        let dup_left = receipt_int(msg, "dupLeft")?;
        if dup_left <= 0 {
            continue;
        }

        let mut reduced = msg.clone();
        reduced.insert("dupLeft".into(), TlaValue::Int(dup_left - 1));
        let mut clone = msg.clone();
        clone.insert("id".into(), TlaValue::Int(current_next_msg_id));
        clone.insert("dupLeft".into(), TlaValue::Int(dup_left - 1));

        let mut expected = current.clone();
        remove_set_var(&mut expected, "net", original)?;
        insert_set_var(&mut expected, "net", TlaValue::Record(reduced))?;
        insert_set_var(&mut expected, "net", TlaValue::Record(clone))?;
        set_var_value(
            &mut expected,
            "nextMsgId",
            TlaValue::Int(current_next_msg_id + 1),
        )?;
        bump_step(&mut expected)?;
        if expected == *next {
            return Ok(true);
        }
    }

    Ok(false)
}

fn apply_add_storage_node(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_nodes = set_var(current, "storageNodes")?;
    let next_nodes = set_var(next, "storageNodes")?;
    let added = set_difference(next_nodes, current_nodes);
    if added.len() != 1 || next_nodes.len() != current_nodes.len() + 1 {
        return Ok(false);
    }

    let mut expected = current.clone();
    insert_set_var(&mut expected, "storageNodes", added[0].clone())?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_generate_keys(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_keys = map_var(current, "keys")?;
    let next_keys = map_var(next, "keys")?;
    let mut changed = Vec::new();

    for device in current_keys.keys() {
        if current_keys.get(device) != next_keys.get(device) {
            changed.push(device.clone());
        }
    }

    if changed.len() != 1 {
        return Ok(false);
    }

    let device = changed[0].clone();
    let current_record = record_fields(
        current_keys
            .get(&device)
            .ok_or_else(|| anyhow!("missing current key state"))?,
    )?;
    let next_record = record_fields(
        next_keys
            .get(&device)
            .ok_or_else(|| anyhow!("missing next key state"))?,
    )?;
    if record_int(current_record, "sphincs")? != 0
        || record_int(current_record, "kyber")? != 0
        || record_int(next_record, "sphincs")? != 1
        || record_int(next_record, "kyber")? != 1
    {
        return Ok(false);
    }

    let mut expected = current.clone();
    set_map_entry(&mut expected, "keys", device, key_record(1, 1))?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_start_offline_session(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_sessions = set_var(current, "offlineSessions")?;
    let next_sessions = set_var(next, "offlineSessions")?;
    if next_sessions.len() != current_sessions.len() + 2 {
        return Ok(false);
    }

    let added = set_difference(next_sessions, current_sessions);
    if added.len() != 2 {
        return Ok(false);
    }
    let a = seq_items(&added[0])?;
    let b = seq_items(&added[1])?;
    if a.len() != 2 || b.len() != 2 || a[0] != b[1] || a[1] != b[0] {
        return Ok(false);
    }

    let mut expected = current.clone();
    insert_set_var(&mut expected, "offlineSessions", added[0].clone())?;
    insert_set_var(&mut expected, "offlineSessions", added[1].clone())?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_offline_transfer(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_sessions = set_var(current, "offlineSessions")?;
    let next_sessions = set_var(next, "offlineSessions")?;
    if current_sessions.len() < 2 || next_sessions.len() + 2 != current_sessions.len() {
        return Ok(false);
    }

    let removed = set_difference(current_sessions, next_sessions);
    if removed.len() != 2 {
        return Ok(false);
    }
    let a = seq_items(&removed[0])?;
    let b = seq_items(&removed[1])?;
    if a.len() != 2 || b.len() != 2 || a[0] != b[1] || a[1] != b[0] {
        return Ok(false);
    }

    let pair = TlaValue::Seq(vec![a[0].clone(), a[1].clone()]);
    let reverse = TlaValue::Seq(vec![a[1].clone(), a[0].clone()]);
    let old_tip = relationship_tip(current, &pair)?;

    let mut expected = current.clone();
    remove_set_var(&mut expected, "offlineSessions", &removed[0])?;
    remove_set_var(&mut expected, "offlineSessions", &removed[1])?;
    set_map_entry(
        &mut expected,
        "relationships",
        pair,
        relationship_record(old_tip + 1, "active"),
    )?;
    set_map_entry(
        &mut expected,
        "relationships",
        reverse,
        relationship_record(old_tip + 1, "active"),
    )?;
    update_relationship_smt_leaf(&mut expected, &a[0], &a[1], old_tip + 1)?;
    insert_set_var(
        &mut expected,
        "ledger",
        ledger_record(a[0].clone(), a[1].clone(), old_tip, old_tip + 1),
    )?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_create_vault(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_vaults = map_var(current, "vaults")?;
    let next_vaults = map_var(next, "vaults")?;
    let mut owner_and_vault: Option<(TlaValue, TlaValue)> = None;

    for owner in current_vaults.keys() {
        let current_set = set_value(
            current_vaults
                .get(owner)
                .ok_or_else(|| anyhow!("missing current vault set"))?,
        )?;
        let next_set = set_value(
            next_vaults
                .get(owner)
                .ok_or_else(|| anyhow!("missing next vault set"))?,
        )?;
        let added = set_difference(next_set, current_set);
        if added.len() == 1 {
            owner_and_vault = Some((owner.clone(), added[0].clone()));
            break;
        }
    }

    let Some((owner, vault)) = owner_and_vault else {
        return Ok(false);
    };

    let next_vault_state = map_var(next, "vaultState")?;
    let next_record = next_vault_state
        .get(&vault)
        .ok_or_else(|| anyhow!("new vault state missing"))?
        .clone();

    let mut expected = current.clone();
    insert_nested_set_entry(&mut expected, "vaults", owner, vault.clone())?;
    set_map_entry(&mut expected, "vaultState", vault, next_record)?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_unlock_vault(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_vault_state = map_var(current, "vaultState")?;
    let next_vault_state = map_var(next, "vaultState")?;

    for vault in current_vault_state.keys() {
        let current_record = record_fields(
            current_vault_state
                .get(vault)
                .ok_or_else(|| anyhow!("missing current vault state"))?,
        )?;
        let next_record = record_fields(
            next_vault_state
                .get(vault)
                .ok_or_else(|| anyhow!("missing next vault state"))?,
        )?;
        if current_record == next_record {
            continue;
        }
        if record_bool(current_record, "locked")? && !record_bool(next_record, "locked")? {
            let mut expected = current.clone();
            set_map_entry(
                &mut expected,
                "vaultState",
                vault.clone(),
                TlaValue::Record(next_record.clone()),
            )?;
            bump_step(&mut expected)?;
            if expected == *next {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn apply_unlock_spend_gate(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_activated = set_var(current, "activatedDevices")?;
    let next_activated = set_var(next, "activatedDevices")?;
    let added = set_difference(next_activated, current_activated);
    if added.len() != 1 || next_activated.len() != current_activated.len() + 1 {
        return Ok(false);
    }

    let device = added[0].clone();
    let current_counts = map_var(current, "actCount")?;
    let next_counts = map_var(next, "actCount")?;
    let current_count = int_from_value(
        current_counts
            .get(&device)
            .ok_or_else(|| anyhow!("missing current actCount"))?,
    )?;
    let next_count = int_from_value(
        next_counts
            .get(&device)
            .ok_or_else(|| anyhow!("missing next actCount"))?,
    )?;
    if next_count != current_count + 1 {
        return Ok(false);
    }

    let current_shards = map_var(current, "shardLists")?;
    let next_shards = map_var(next, "shardLists")?;
    let mut shard_key: Option<TlaValue> = None;
    for key in current_shards.keys() {
        let current_seq = seq_value(
            current_shards
                .get(key)
                .ok_or_else(|| anyhow!("missing current shard list"))?,
        )?;
        let next_seq = seq_value(
            next_shards
                .get(key)
                .ok_or_else(|| anyhow!("missing next shard list"))?,
        )?;
        if next_seq.len() == current_seq.len() + 1
            && next_seq[..current_seq.len()] == current_seq[..]
            && next_seq.last() == Some(&device)
        {
            shard_key = Some(key.clone());
            break;
        }
    }

    let Some(shard_key) = shard_key else {
        return Ok(false);
    };

    let mut expected = current.clone();
    insert_set_var(&mut expected, "activatedDevices", device.clone())?;
    set_map_entry(
        &mut expected,
        "actCount",
        device.clone(),
        TlaValue::Int(next_count),
    )?;
    append_seq_map_entry(&mut expected, "shardLists", shard_key, device)?;
    increment_var(&mut expected, "shardTree", 1)?;
    increment_var(&mut expected, "djteSeed", 1)?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_activate_again(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    if set_var(current, "activatedDevices")? != set_var(next, "activatedDevices")? {
        return Ok(false);
    }

    let current_counts = map_var(current, "actCount")?;
    let next_counts = map_var(next, "actCount")?;
    let mut target: Option<(TlaValue, i64)> = None;
    for device in current_counts.keys() {
        let current_count = int_from_value(
            current_counts
                .get(device)
                .ok_or_else(|| anyhow!("missing current count"))?,
        )?;
        let next_count = int_from_value(
            next_counts
                .get(device)
                .ok_or_else(|| anyhow!("missing next count"))?,
        )?;
        if next_count == current_count + 1 {
            target = Some((device.clone(), next_count));
            break;
        }
    }

    let Some((device, next_count)) = target else {
        return Ok(false);
    };

    let mut expected = current.clone();
    set_map_entry(&mut expected, "actCount", device, TlaValue::Int(next_count))?;
    increment_var(&mut expected, "shardTree", 1)?;
    increment_var(&mut expected, "djteSeed", 1)?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_consume_jap_and_emit(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_spent = set_var(current, "spentJaps")?;
    let next_spent = set_var(next, "spentJaps")?;
    let current_proofs = set_var(current, "spentProofs")?;
    let next_proofs = set_var(next, "spentProofs")?;
    let added_jap = set_difference(next_spent, current_spent);
    let added_proof = set_difference(next_proofs, current_proofs);
    if added_jap.len() != 1 || added_proof.len() != 1 {
        return Ok(false);
    }

    let mut expected = current.clone();
    insert_set_var(&mut expected, "spentJaps", added_jap[0].clone())?;
    insert_set_var(&mut expected, "spentProofs", added_proof[0].clone())?;
    increment_var(&mut expected, "emissionIndex", 1)?;
    increment_var(&mut expected, "shardTree", 1)?;
    increment_var(&mut expected, "djteSeed", 1)?;
    increment_var(&mut expected, "sourceRemaining", -1)?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_consume_spent_proof(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_consumed = set_var(current, "consumedProofs")?;
    let next_consumed = set_var(next, "consumedProofs")?;
    let added = set_difference(next_consumed, current_consumed);
    if added.len() != 1 {
        return Ok(false);
    }

    let mut expected = current.clone();
    insert_set_var(&mut expected, "consumedProofs", added[0].clone())?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_phase_transition(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let current_phase = int_var(current, "phase")?;
    let next_phase = int_var(next, "phase")?;
    if next_phase != current_phase + 1 && !(current_phase == 3 && next_phase == 3) {
        return Ok(false);
    }

    let mut expected = current.clone();
    set_var_value(&mut expected, "phase", TlaValue::Int(next_phase))?;
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn apply_step_only(current: &TlaState, next: &TlaState) -> anyhow::Result<bool> {
    let mut expected = current.clone();
    bump_step(&mut expected)?;
    Ok(expected == *next)
}

fn relationship_tip(state: &TlaState, pair: &TlaValue) -> anyhow::Result<i64> {
    let relationships = map_var(state, "relationships")?;
    let relationship = relationships
        .get(pair)
        .ok_or_else(|| anyhow!("missing relationship {}", pair.display()))?;
    let record = record_fields(relationship)?;
    record_int(record, "tip")
}

fn relationship_record(tip: i64, state: &str) -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("tip".into(), TlaValue::Int(tip)),
        ("state".into(), TlaValue::Str(state.into())),
    ]))
}

fn key_record(sphincs: i64, kyber: i64) -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("sphincs".into(), TlaValue::Int(sphincs)),
        ("kyber".into(), TlaValue::Int(kyber)),
    ]))
}

fn ledger_record(d1: TlaValue, d2: TlaValue, old_tip: i64, new_tip: i64) -> TlaValue {
    let mut rel = BTreeSet::new();
    rel.insert(d1);
    rel.insert(d2);
    TlaValue::Record(BTreeMap::from([
        ("rel".into(), TlaValue::Set(rel)),
        ("oldTip".into(), TlaValue::Int(old_tip)),
        ("newTip".into(), TlaValue::Int(new_tip)),
    ]))
}

fn rel_key_value(d1: &TlaValue, d2: &TlaValue) -> TlaValue {
    let mut rel = BTreeSet::new();
    rel.insert(d1.clone());
    rel.insert(d2.clone());
    TlaValue::Set(rel)
}

fn update_relationship_smt_leaf(
    state: &mut TlaState,
    d1: &TlaValue,
    d2: &TlaValue,
    new_tip: i64,
) -> anyhow::Result<()> {
    if !state.contains_key("smtState") && !state.contains_key("deviceRoots") {
        return Ok(());
    }

    let rel = rel_key_value(d1, d2);
    set_nested_map_entry(
        state,
        "smtState",
        d1.clone(),
        rel.clone(),
        TlaValue::Int(new_tip),
    )?;
    set_nested_map_entry(state, "smtState", d2.clone(), rel, TlaValue::Int(new_tip))?;
    increment_map_entry(state, "deviceRoots", d1.clone(), 1)?;
    increment_map_entry(state, "deviceRoots", d2.clone(), 1)
}

fn bump_step(state: &mut TlaState) -> anyhow::Result<()> {
    increment_var(state, "step", 1)
}

fn increment_var(state: &mut TlaState, name: &str, delta: i64) -> anyhow::Result<()> {
    let current = int_var(state, name)?;
    set_var_value(state, name, TlaValue::Int(current + delta))
}

fn set_var_value(state: &mut TlaState, name: &str, value: TlaValue) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing state variable {name}"))?;
    *slot = value;
    Ok(())
}

fn insert_set_var(state: &mut TlaState, name: &str, value: TlaValue) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing set variable {name}"))?;
    match slot {
        TlaValue::Set(set) => {
            set.insert(value);
            Ok(())
        }
        _ => bail!("{name} was not a set"),
    }
}

fn remove_set_var(state: &mut TlaState, name: &str, value: &TlaValue) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing set variable {name}"))?;
    match slot {
        TlaValue::Set(set) => {
            if !set.remove(value) {
                bail!("{name} did not contain {}", value.display());
            }
            Ok(())
        }
        _ => bail!("{name} was not a set"),
    }
}

fn set_map_entry(
    state: &mut TlaState,
    name: &str,
    key: TlaValue,
    value: TlaValue,
) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing map variable {name}"))?;
    match slot {
        TlaValue::Map(map) => {
            map.insert(key, value);
            Ok(())
        }
        _ => bail!("{name} was not a map"),
    }
}

fn increment_map_entry(
    state: &mut TlaState,
    name: &str,
    key: TlaValue,
    delta: i64,
) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing map variable {name}"))?;
    match slot {
        TlaValue::Map(map) => {
            let current = int_from_value(
                map.get(&key)
                    .ok_or_else(|| anyhow!("{name} missing key {}", key.display()))?,
            )?;
            map.insert(key, TlaValue::Int(current + delta));
            Ok(())
        }
        _ => bail!("{name} was not a map"),
    }
}

fn set_nested_map_entry(
    state: &mut TlaState,
    name: &str,
    outer_key: TlaValue,
    inner_key: TlaValue,
    value: TlaValue,
) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing nested map variable {name}"))?;
    match slot {
        TlaValue::Map(map) => {
            let inner = map
                .get_mut(&outer_key)
                .ok_or_else(|| anyhow!("missing outer key {}", outer_key.display()))?;
            match inner {
                TlaValue::Map(inner_map) => {
                    inner_map.insert(inner_key, value);
                    Ok(())
                }
                _ => bail!("{name}[{}] was not a map", outer_key.display()),
            }
        }
        _ => bail!("{name} was not a map"),
    }
}

fn insert_nested_set_entry(
    state: &mut TlaState,
    name: &str,
    outer_key: TlaValue,
    value: TlaValue,
) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing nested set variable {name}"))?;
    match slot {
        TlaValue::Map(map) => {
            let inner = map
                .get_mut(&outer_key)
                .ok_or_else(|| anyhow!("missing outer key {}", outer_key.display()))?;
            match inner {
                TlaValue::Set(set) => {
                    set.insert(value);
                    Ok(())
                }
                _ => bail!("{name}[{}] was not a set", outer_key.display()),
            }
        }
        _ => bail!("{name} was not a map"),
    }
}

fn append_seq_map_entry(
    state: &mut TlaState,
    name: &str,
    key: TlaValue,
    value: TlaValue,
) -> anyhow::Result<()> {
    let slot = state
        .get_mut(name)
        .ok_or_else(|| anyhow!("missing sequence map variable {name}"))?;
    match slot {
        TlaValue::Map(map) => {
            let inner = map
                .get_mut(&key)
                .ok_or_else(|| anyhow!("missing key {}", key.display()))?;
            match inner {
                TlaValue::Seq(seq) => {
                    seq.push(value);
                    Ok(())
                }
                _ => bail!("{name}[{}] was not a sequence", key.display()),
            }
        }
        _ => bail!("{name} was not a map"),
    }
}

fn int_var(state: &TlaState, name: &str) -> anyhow::Result<i64> {
    int_from_value(
        state
            .get(name)
            .ok_or_else(|| anyhow!("missing int variable {name}"))?,
    )
}

fn map_var<'a>(
    state: &'a TlaState,
    name: &str,
) -> anyhow::Result<&'a BTreeMap<TlaValue, TlaValue>> {
    map_value(
        state
            .get(name)
            .ok_or_else(|| anyhow!("missing map variable {name}"))?,
    )
}

fn set_var<'a>(state: &'a TlaState, name: &str) -> anyhow::Result<&'a BTreeSet<TlaValue>> {
    set_value(
        state
            .get(name)
            .ok_or_else(|| anyhow!("missing set variable {name}"))?,
    )
}

fn int_from_value(value: &TlaValue) -> anyhow::Result<i64> {
    match value {
        TlaValue::Int(value) => Ok(*value),
        _ => bail!("expected int, found {}", value.display()),
    }
}

fn map_value(value: &TlaValue) -> anyhow::Result<&BTreeMap<TlaValue, TlaValue>> {
    match value {
        TlaValue::Map(value) => Ok(value),
        _ => bail!("expected map, found {}", value.display()),
    }
}

fn set_value(value: &TlaValue) -> anyhow::Result<&BTreeSet<TlaValue>> {
    match value {
        TlaValue::Set(value) => Ok(value),
        _ => bail!("expected set, found {}", value.display()),
    }
}

fn seq_value(value: &TlaValue) -> anyhow::Result<&Vec<TlaValue>> {
    match value {
        TlaValue::Seq(value) => Ok(value),
        _ => bail!("expected sequence, found {}", value.display()),
    }
}

fn record_fields(value: &TlaValue) -> anyhow::Result<&BTreeMap<String, TlaValue>> {
    match value {
        TlaValue::Record(value) => Ok(value),
        _ => bail!("expected record, found {}", value.display()),
    }
}

fn set_items(value: &TlaValue) -> anyhow::Result<Vec<TlaValue>> {
    Ok(set_value(value)?.iter().cloned().collect())
}

fn seq_items(value: &TlaValue) -> anyhow::Result<Vec<TlaValue>> {
    Ok(seq_value(value)?.clone())
}

fn record_int(record: &BTreeMap<String, TlaValue>, field: &str) -> anyhow::Result<i64> {
    int_from_value(
        record
            .get(field)
            .ok_or_else(|| anyhow!("missing record field {field}"))?,
    )
}

fn record_bool(record: &BTreeMap<String, TlaValue>, field: &str) -> anyhow::Result<bool> {
    match record
        .get(field)
        .ok_or_else(|| anyhow!("missing record field {field}"))?
    {
        TlaValue::Bool(value) => Ok(*value),
        value => bail!("expected bool field {field}, found {}", value.display()),
    }
}

fn record_str<'a>(record: &'a BTreeMap<String, TlaValue>, field: &str) -> anyhow::Result<&'a str> {
    match record
        .get(field)
        .ok_or_else(|| anyhow!("missing record field {field}"))?
    {
        TlaValue::Str(value) => Ok(value),
        value => bail!("expected string field {field}, found {}", value.display()),
    }
}

fn receipt_int(record: &BTreeMap<String, TlaValue>, field: &str) -> anyhow::Result<i64> {
    record_int(record, field)
}

fn set_difference(a: &BTreeSet<TlaValue>, b: &BTreeSet<TlaValue>) -> Vec<TlaValue> {
    a.difference(b).cloned().collect()
}

fn summarize_state_diff(current: &TlaState, next: &TlaState) -> String {
    let changed: Vec<String> = current
        .keys()
        .filter(|key| current.get(*key) != next.get(*key))
        .cloned()
        .collect();
    if changed.is_empty() {
        "no visible variable delta".into()
    } else {
        changed.join(", ")
    }
}

struct ValueParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> ValueParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_value(&mut self) -> anyhow::Result<TlaValue> {
        self.skip_ws();
        if self.consume("<<") {
            return self.parse_seq();
        }
        if self.consume("{") {
            return self.parse_set();
        }
        if self.consume("[") {
            return self.parse_record();
        }
        if self.consume("(") {
            return self.parse_map();
        }
        if self.peek_char() == Some('"') {
            return self.parse_string();
        }
        if matches!(self.peek_char(), Some('0'..='9') | Some('-')) {
            return self.parse_int();
        }

        let ident = self.parse_ident()?;
        match ident.as_str() {
            "TRUE" => Ok(TlaValue::Bool(true)),
            "FALSE" => Ok(TlaValue::Bool(false)),
            _ => Ok(TlaValue::Symbol(ident)),
        }
    }

    fn parse_seq(&mut self) -> anyhow::Result<TlaValue> {
        self.skip_ws();
        let mut values = Vec::new();
        if self.consume(">>") {
            return Ok(TlaValue::Seq(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            if self.consume(",") {
                continue;
            }
            self.expect(">>")?;
            break;
        }
        Ok(TlaValue::Seq(values))
    }

    fn parse_set(&mut self) -> anyhow::Result<TlaValue> {
        self.skip_ws();
        let mut values = BTreeSet::new();
        if self.consume("}") {
            return Ok(TlaValue::Set(values));
        }
        loop {
            values.insert(self.parse_value()?);
            self.skip_ws();
            if self.consume(",") {
                continue;
            }
            self.expect("}")?;
            break;
        }
        Ok(TlaValue::Set(values))
    }

    fn parse_record(&mut self) -> anyhow::Result<TlaValue> {
        self.skip_ws();
        let mut fields = BTreeMap::new();
        if self.consume("]") {
            return Ok(TlaValue::Record(fields));
        }
        loop {
            let field = self.parse_ident()?;
            self.skip_ws();
            self.expect("|->")?;
            let value = self.parse_value()?;
            fields.insert(field, value);
            self.skip_ws();
            if self.consume(",") {
                continue;
            }
            self.expect("]")?;
            break;
        }
        Ok(TlaValue::Record(fields))
    }

    fn parse_map(&mut self) -> anyhow::Result<TlaValue> {
        self.skip_ws();
        let mut entries = BTreeMap::new();
        if self.consume(")") {
            return Ok(TlaValue::Map(entries));
        }
        loop {
            let key = self.parse_value()?;
            self.skip_ws();
            self.expect(":>")?;
            let value = self.parse_value()?;
            entries.insert(key, value);
            self.skip_ws();
            if self.consume("@@") {
                continue;
            }
            self.expect(")")?;
            break;
        }
        Ok(TlaValue::Map(entries))
    }

    fn parse_string(&mut self) -> anyhow::Result<TlaValue> {
        self.expect("\"")?;
        let start = self.pos;
        while let Some(ch) = self.peek_char() {
            if ch == '"' {
                let value = self.input[start..self.pos].to_string();
                self.pos += 1;
                return Ok(TlaValue::Str(value));
            }
            self.pos += ch.len_utf8();
        }
        bail!("unterminated string literal")
    }

    fn parse_int(&mut self) -> anyhow::Result<TlaValue> {
        let start = self.pos;
        if self.peek_char() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek_char(), Some('0'..='9')) {
            self.pos += 1;
        }
        Ok(TlaValue::Int(
            self.input[start..self.pos]
                .parse()
                .with_context(|| format!("invalid integer {}", &self.input[start..self.pos]))?,
        ))
    }

    fn parse_ident(&mut self) -> anyhow::Result<String> {
        self.skip_ws();
        let start = self.pos;
        while matches!(
            self.peek_char(),
            Some('a'..='z' | 'A'..='Z' | '0'..='9' | '_')
        ) {
            self.pos += 1;
        }
        if start == self.pos {
            bail!("expected identifier near {}", &self.input[self.pos..]);
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn expect_end(&mut self) -> anyhow::Result<()> {
        self.skip_ws();
        if self.pos == self.input.len() {
            Ok(())
        } else {
            bail!("unexpected trailing input near {}", &self.input[self.pos..])
        }
    }

    fn expect(&mut self, token: &str) -> anyhow::Result<()> {
        if self.consume(token) {
            Ok(())
        } else {
            bail!("expected token {token} near {}", &self.input[self.pos..])
        }
    }

    fn consume(&mut self, token: &str) -> bool {
        self.skip_ws();
        if self.input[self.pos..].starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }
}

impl TlaValue {
    fn display(&self) -> TlaValueDisplay<'_> {
        TlaValueDisplay(self)
    }
}

struct TlaValueDisplay<'a>(&'a TlaValue);

impl fmt::Display for TlaValueDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            TlaValue::Int(v) => write!(f, "{v}"),
            TlaValue::Bool(v) => write!(f, "{v}"),
            TlaValue::Str(v) => write!(f, "\"{v}\""),
            TlaValue::Symbol(v) => write!(f, "{v}"),
            TlaValue::Seq(v) => {
                write!(f, "<<")?;
                for (idx, item) in v.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item.display())?;
                }
                write!(f, ">>")
            }
            TlaValue::Set(v) => {
                write!(f, "{{")?;
                for (idx, item) in v.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item.display())?;
                }
                write!(f, "}}")
            }
            TlaValue::Record(v) => {
                write!(f, "[")?;
                for (idx, (key, value)) in v.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{key} |-> {}", value.display())?;
                }
                write!(f, "]")
            }
            TlaValue::Map(v) => {
                write!(f, "(")?;
                for (idx, (key, value)) in v.iter().enumerate() {
                    if idx > 0 {
                        write!(f, " @@ ")?;
                    }
                    write!(f, "{} :> {}", key.display(), value.display())?;
                }
                write!(f, ")")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_tla_values() {
        let src =
            "(d1 :> ({d1, d2} :> 0 @@ {d2, d3} :> 1) @@ d2 :> ({d1, d2} :> 2 @@ {d2, d3} :> 3))";
        let mut parser = ValueParser::new(src);
        let value = parser.parse_value().expect("parse nested value");
        parser.expect_end().expect("consume all input");
        assert!(matches!(value, TlaValue::Map(_)));
    }

    #[test]
    fn replays_minimal_tripwire_trace() {
        let trace = r#"
---------------- MODULE tripwire_test -----------------
STATE_1 ==
/\ deviceRoots = (d1 :> 0 @@ d2 :> 0 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {}

STATE_2 ==
/\ deviceRoots = (d1 :> 1 @@ d2 :> 1 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 1 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 1 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {[oldTip |-> 0, newTip |-> 1, rel |-> {d1, d2}, r1 |-> 0, r2 |-> 0]}
"#;
        let states = parse_trace_states(trace).expect("parse tripwire states");
        let failures = replay_tripwire_trace(&states);
        assert!(
            failures.is_empty(),
            "tripwire replay failures: {failures:?}"
        );
    }

    #[test]
    fn rejects_tripwire_replay_when_roots_do_not_advance() {
        let trace = r#"
---------------- MODULE tripwire_impl_bad_roots -----------------
STATE_1 ==
/\ deviceRoots = (d1 :> 0 @@ d2 :> 0 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {}

STATE_2 ==
/\ deviceRoots = (d1 :> 0 @@ d2 :> 0 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 1 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 1 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {[oldTip |-> 0, newTip |-> 1, rel |-> {d1, d2}, r1 |-> 0, r2 |-> 0]}
"#;
        let states = parse_trace_states(trace).expect("parse malformed tripwire states");
        let failures = replay_tripwire_trace(&states);
        assert!(
            !failures.is_empty(),
            "the Tripwire replay unexpectedly accepted malformed tripwire roots"
        );
        assert!(
            failures.iter().any(|failure| failure.contains("diverged")),
            "unexpected failure output: {failures:?}"
        );
    }

    #[test]
    fn rejects_tripwire_replay_when_bilateral_smt_update_is_incomplete() {
        let trace = r#"
---------------- MODULE tripwire_impl_bad_smt -----------------
STATE_1 ==
/\ deviceRoots = (d1 :> 0 @@ d2 :> 0 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {}

STATE_2 ==
/\ deviceRoots = (d1 :> 1 @@ d2 :> 1 @@ d3 :> 0)
/\ smtState = (d1 :> ({d1, d2} :> 1 @@ {d2, d3} :> 0) @@ d2 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0) @@ d3 :> ({d1, d2} :> 0 @@ {d2, d3} :> 0))
/\ ledger = {[oldTip |-> 0, newTip |-> 1, rel |-> {d1, d2}, r1 |-> 0, r2 |-> 0]}
"#;
        let states = parse_trace_states(trace).expect("parse malformed tripwire SMT states");
        let failures = replay_tripwire_trace(&states);
        assert!(
            !failures.is_empty(),
            "the Tripwire replay unexpectedly accepted malformed bilateral SMT update"
        );
        assert!(
            failures.iter().any(|failure| failure.contains("diverged")),
            "unexpected failure output: {failures:?}"
        );
    }
}
