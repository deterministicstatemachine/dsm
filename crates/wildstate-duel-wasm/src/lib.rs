// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebAssembly bindings of the Wildstate duel outcome program.
//!
//! The game server resolves every staked match through these exports, so the
//! screen and the escrow run the same compiled rules. Objects cross the
//! boundary as their canonical CCB bytes (`Uint8Array`); the plain objects
//! returned by `step`, `replay`, `stateView` and `outcome` are display views
//! of those bytes, never inputs to the program.

use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wildstate_duel::creatures::CreatureRecordV1;
use wildstate_duel::vectors::DuelVectorSetV1;
use wildstate_duel::{
    Acted, ActionLog, CreatureStateV1, DuelMatchV1, DuelMoveV1, DuelOpenedTurnV1, DuelSetupV1,
    DuelSide, DuelState, DuelTurnV1, End, Event, EventKind, Fighter, Guard, Phase, Played, Side,
    SideState, TurnLog, Winner, TABLES,
};

fn fail(what: impl core::fmt::Display) -> JsError {
    JsError::new(&what.to_string())
}

fn get(o: &JsValue, key: &str) -> Result<JsValue, JsError> {
    let v = Reflect::get(o, &JsValue::from_str(key)).map_err(|e| fail(format!("{key}: {e:?}")))?;
    if v.is_undefined() {
        return Err(fail(format!("{key} is missing")));
    }
    Ok(v)
}

fn int<T: TryFrom<u64>>(o: &JsValue, key: &str) -> Result<T, JsError>
where
    T::Error: core::fmt::Display,
{
    let v = get(o, key)?
        .as_f64()
        .ok_or_else(|| fail(format!("{key} is not a number")))?;
    if v.fract() != 0.0 || !(0.0..=4_294_967_295.0).contains(&v) {
        return Err(fail(format!("{key} is not a whole number in range")));
    }
    T::try_from(v as u64).map_err(|e| fail(format!("{key}: {e}")))
}

fn bytes_of(v: &JsValue, key: &str) -> Result<Vec<u8>, JsError> {
    if !v.is_instance_of::<Uint8Array>() {
        return Err(fail(format!("{key} is not a Uint8Array")));
    }
    Ok(Uint8Array::new(v).to_vec())
}

fn bytes(o: &JsValue, key: &str) -> Result<Vec<u8>, JsError> {
    bytes_of(&get(o, key)?, key)
}

fn digest(o: &JsValue, key: &str) -> Result<[u8; 32], JsError> {
    let b = bytes(o, key)?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|e| fail(format!("{key}: {e}")))
}

fn set(o: &Object, key: &str, v: impl Into<JsValue>) -> Result<(), JsError> {
    let done = Reflect::set(o, &JsValue::from_str(key), &v.into())
        .map_err(|e| fail(format!("{key}: {e:?}")))?;
    if done {
        Ok(())
    } else {
        Err(fail(format!("{key} could not be set")))
    }
}

fn u8a(b: &[u8]) -> Uint8Array {
    Uint8Array::from(b)
}

fn side_name(s: Side) -> &'static str {
    match s {
        Side::A => "a",
        Side::B => "b",
    }
}

fn end_name(e: End) -> &'static str {
    match e {
        End::Knockouts => "knockouts",
        End::Resign => "resign",
        End::Hp => "hp",
        End::Tiebreak => "tiebreak",
    }
}

fn status_name(id: u8) -> JsValue {
    TABLES
        .statuses
        .get(usize::from(id))
        .map_or(JsValue::NULL, |s| JsValue::from_str(s.id))
}

fn creature_of(c: &JsValue) -> Result<CreatureStateV1, JsError> {
    let charges = get(c, "charges")?;
    let charges = if charges.is_instance_of::<Uint8Array>() {
        bytes_of(&charges, "charges")?
    } else {
        let list = Array::from(&charges);
        let mut out = Vec::new();
        for (i, n) in list.iter().enumerate() {
            let n = n
                .as_f64()
                .ok_or_else(|| fail(format!("charges[{i}] is not a number")))?;
            if n.fract() != 0.0 || !(0.0..=255.0).contains(&n) {
                return Err(fail(format!("charges[{i}] is not a byte")));
            }
            out.push(n as u8);
        }
        out
    };
    CreatureStateV1::new(
        digest(c, "anchor")?,
        int(c, "species")?,
        int(c, "xp")?,
        int(c, "hp")?,
        charges,
    )
    .map_err(fail)
}

fn team_of(v: &JsValue) -> Result<Vec<CreatureStateV1>, JsError> {
    let arr = Array::from(&get(v, "team")?);
    let mut team = Vec::new();
    for c in arr.iter() {
        if c.is_instance_of::<Uint8Array>() {
            team.push(CreatureStateV1::decode(&bytes_of(&c, "team[]")?).map_err(fail)?);
            continue;
        }
        team.push(creature_of(&c)?);
    }
    Ok(team)
}

fn side_of(o: &JsValue, key: &str) -> Result<DuelSide, JsError> {
    let v = get(o, key)?;
    Ok(DuelSide {
        genesis: digest(&v, "genesis")?,
        device_id: digest(&v, "deviceId")?,
        session_public_key: bytes(&v, "sessionPublicKey")?,
        poultice: int(&v, "poultice")?,
        tonic: int(&v, "tonic")?,
        team: team_of(&v)?,
    })
}

/// The canonical setup bytes of `{ program, matchNonce, turnCap, tiebreakSeed,
/// a, b }`; a side is `{ genesis, deviceId, sessionPublicKey, poultice, tonic,
/// team }` and a creature `{ anchor, species, xp, hp, charges }`.
#[wasm_bindgen(js_name = encodeSetup)]
pub fn encode_setup(setup: JsValue) -> Result<Uint8Array, JsError> {
    let body = DuelMatchV1::new(
        digest(&setup, "matchNonce")?,
        int(&setup, "turnCap")?,
        digest(&setup, "tiebreakSeed")?,
        side_of(&setup, "a")?,
        side_of(&setup, "b")?,
    )
    .map_err(fail)?;
    let s = DuelSetupV1 {
        program: digest(&setup, "program")?,
        body,
    };
    Ok(u8a(&s.encode()))
}

/// The canonical bytes of one move: `{ kind: 'move', index }`, `{ kind:
/// 'item', item, teamIndex }`, `{ kind: 'pass' }` or `{ kind: 'resign' }`.
#[wasm_bindgen(js_name = encodeMove)]
pub fn encode_move(mv: JsValue) -> Result<Uint8Array, JsError> {
    let kind = get(&mv, "kind")?
        .as_string()
        .ok_or_else(|| fail("kind is not a string"))?;
    let m = match kind.as_str() {
        "move" => DuelMoveV1::Move {
            index: int(&mv, "index")?,
        },
        "item" => DuelMoveV1::Item {
            item: int(&mv, "item")?,
            team_index: int(&mv, "teamIndex")?,
        },
        "pass" => DuelMoveV1::Pass,
        "resign" => DuelMoveV1::Resign,
        other => return Err(fail(format!("unknown move kind {other}"))),
    };
    Ok(u8a(&m.encode()))
}

/// The canonical bytes of the move an opening plays: the move it is the
/// canonical encoding of, and a pass for any other bytes.
#[wasm_bindgen(js_name = playedMove)]
pub fn played_move(opened: &[u8]) -> Uint8Array {
    u8a(&DuelMoveV1::played(opened).encode())
}

/// The turn's canonical bytes the rules play from both sides' openings,
/// exactly as revealed: each plays as `playedMove` reads it.
#[wasm_bindgen(js_name = turnOfOpenings)]
pub fn turn_of_openings(a: &[u8], b: &[u8]) -> Uint8Array {
    let opened = DuelOpenedTurnV1 {
        a: a.to_vec(),
        b: b.to_vec(),
    };
    u8a(&opened.turn().encode())
}

/// A turn's canonical bytes from both sides' move bytes.
#[wasm_bindgen(js_name = encodeTurn)]
pub fn encode_turn(a: &[u8], b: &[u8]) -> Result<Uint8Array, JsError> {
    let t = DuelTurnV1 {
        a: DuelMoveV1::decode(a).map_err(fail)?,
        b: DuelMoveV1::decode(b).map_err(fail)?,
    };
    Ok(u8a(&t.encode()))
}

/// The state before turn 0 of a setup that pins this program.
#[wasm_bindgen(js_name = startState)]
pub fn start_state(setup: &[u8]) -> Result<Uint8Array, JsError> {
    Ok(u8a(&wildstate_duel::start(setup).map_err(fail)?.encode()))
}

/// One turn on a kept state: `{ state, log }`.
#[wasm_bindgen]
pub fn step(state: &[u8], turn: &[u8]) -> Result<JsValue, JsError> {
    let s = DuelState::decode(state).map_err(fail)?;
    let t = DuelTurnV1::decode(turn).map_err(fail)?;
    let (next, log) = s.step_logged(&t).map_err(fail)?;
    let o = Object::new();
    set(&o, "state", u8a(&next.encode()))?;
    set(&o, "log", log_view(&log)?)?;
    Ok(o.into())
}

fn turns_of(turns: &Array) -> Result<Vec<DuelTurnV1>, JsError> {
    let mut out = Vec::new();
    for (i, t) in turns.iter().enumerate() {
        out.push(DuelTurnV1::decode(&bytes_of(&t, &format!("turns[{i}]"))?).map_err(fail)?);
    }
    Ok(out)
}

/// Every turn's log of a transcript (which may stop before the match is decided).
#[wasm_bindgen]
pub fn replay(setup: &[u8], turns: Array) -> Result<Array, JsError> {
    let logs = wildstate_duel::replay(setup, &turns_of(&turns)?).map_err(fail)?;
    let out = Array::new();
    for l in &logs {
        out.push(&log_view(l)?.into());
    }
    Ok(out)
}

/// The decided result of a complete transcript: `{ winner, end, turns }`.
#[wasm_bindgen]
pub fn outcome(setup: &[u8], turns: Array) -> Result<JsValue, JsError> {
    let w = wildstate_duel::outcome(setup, &turns_of(&turns)?).map_err(fail)?;
    Ok(winner_view(&w)?.into())
}

#[wasm_bindgen(js_name = programHash)]
pub fn program_hash() -> Uint8Array {
    u8a(&wildstate_duel::program_hash())
}

/// The tiebreak seed a staked match's setup commits, from its nonce and both
/// sides' session public keys (`wildstate_duel::tiebreak_seed`).
#[wasm_bindgen(js_name = tiebreakSeed)]
pub fn tiebreak_seed(
    match_nonce: &[u8],
    session_a: &[u8],
    session_b: &[u8],
) -> Result<Uint8Array, JsError> {
    let nonce: [u8; 32] = match_nonce
        .try_into()
        .map_err(|e| JsError::new(&format!("a match nonce is 32 bytes: {e}")))?;
    Ok(u8a(&wildstate_duel::tiebreak_seed(
        &nonce, session_a, session_b,
    )))
}

#[wasm_bindgen(js_name = tablesDigest)]
pub fn tables_digest() -> Uint8Array {
    u8a(&wildstate_duel::tables_digest())
}

/// The canonical tables bytes the tables digest is taken over.
#[wasm_bindgen(js_name = tablesEncoding)]
pub fn tables_encoding() -> Uint8Array {
    u8a(&TABLES.encode())
}

/// The tables digest of tables bytes encoded elsewhere (the game's own tables).
#[wasm_bindgen(js_name = tablesDigestOf)]
pub fn tables_digest_of(ccb: &[u8]) -> Uint8Array {
    u8a(&wildstate_duel::tables::tables_digest_of(ccb))
}

/// Runs the frozen vectors; their count when every one reproduces.
#[wasm_bindgen(js_name = verifyConformance)]
pub fn verify_conformance() -> Result<u32, JsError> {
    let n = wildstate_duel::verify_conformance().map_err(fail)?;
    u32::try_from(n).map_err(fail)
}

/// The frozen vectors as setups under this program:
/// `[{ label, setup, turns, winner, end, finalState }]`.
#[wasm_bindgen(js_name = conformanceVectors)]
pub fn conformance_vectors() -> Result<Array, JsError> {
    let frozen = DuelVectorSetV1::decode(wildstate_duel::VECTORS_V1).map_err(fail)?;
    let p = wildstate_duel::program_hash();
    let out = Array::new();
    for v in &frozen.vectors {
        let o = Object::new();
        set(&o, "label", String::from_utf8_lossy(&v.label).into_owned())?;
        let setup = DuelSetupV1 {
            program: p,
            body: v.body.clone(),
        };
        set(&o, "setup", u8a(&setup.encode()))?;
        let turns = Array::new();
        for t in &v.turns {
            turns.push(&u8a(&t.encode()));
        }
        set(&o, "turns", turns)?;
        let opened = Array::new();
        for t in &v.opened {
            let pair = Object::new();
            set(&pair, "a", u8a(&t.a))?;
            set(&pair, "b", u8a(&t.b))?;
            opened.push(&pair);
        }
        set(&o, "opened", opened)?;
        set(&o, "winner", side_name(v.winner))?;
        set(&o, "end", end_name(v.end))?;
        set(&o, "finalState", u8a(&v.final_state))?;
        out.push(&o);
    }
    Ok(out)
}

fn move_view(m: DuelMoveV1) -> Result<Object, JsError> {
    let o = Object::new();
    match m {
        DuelMoveV1::Move { index } => {
            set(&o, "kind", "move")?;
            set(&o, "index", index)?;
        }
        DuelMoveV1::Item { item, team_index } => {
            set(&o, "kind", "item")?;
            set(&o, "item", item)?;
            set(&o, "teamIndex", team_index)?;
        }
        DuelMoveV1::Pass => set(&o, "kind", "pass")?,
        DuelMoveV1::Resign => set(&o, "kind", "resign")?,
    }
    Ok(o)
}

/// A display view of a turn's bytes: `{ a, b }`, each as `encodeMove` takes it.
#[wasm_bindgen(js_name = turnView)]
pub fn turn_view(turn: &[u8]) -> Result<JsValue, JsError> {
    let t = DuelTurnV1::decode(turn).map_err(fail)?;
    let o = Object::new();
    set(&o, "a", move_view(t.a)?)?;
    set(&o, "b", move_view(t.b)?)?;
    Ok(o.into())
}

/// The state digest of kept state bytes.
#[wasm_bindgen(js_name = stateDigest)]
pub fn state_digest(state: &[u8]) -> Result<Uint8Array, JsError> {
    Ok(u8a(&DuelState::decode(state).map_err(fail)?.digest()))
}

/// A display view of kept state bytes.
#[wasm_bindgen(js_name = stateView)]
pub fn state_view(state: &[u8]) -> Result<JsValue, JsError> {
    let s = DuelState::decode(state).map_err(fail)?;
    let o = Object::new();
    set(&o, "turn", s.turn())?;
    match s.phase() {
        Phase::Battle => set(&o, "winner", JsValue::NULL)?,
        Phase::Done(w) => set(&o, "winner", winner_view(&w)?)?,
    }
    set(&o, "a", side_view(s.side(Side::A))?)?;
    set(&o, "b", side_view(s.side(Side::B))?)?;
    Ok(o.into())
}

fn side_view(s: &SideState) -> Result<Object, JsError> {
    let o = Object::new();
    let [poultice, tonic] = s.items();
    set(&o, "poultice", poultice)?;
    set(&o, "tonic", tonic)?;
    set(&o, "active", s.active())?;
    set(&o, "ko", s.ko())?;
    let team = Array::new();
    for f in s.team() {
        team.push(&fighter_view(f)?.into());
    }
    set(&o, "team", team)?;
    Ok(o)
}

fn fighter_view(f: &Fighter) -> Result<Object, JsError> {
    let o = Object::new();
    let c = f.creature();
    set(&o, "species", c.species_def().id)?;
    set(&o, "xp", c.xp())?;
    set(&o, "hp", c.hp())?;
    let charges = Array::new();
    for n in c.charges() {
        charges.push(&JsValue::from(*n));
    }
    set(&o, "charges", charges)?;
    set(
        &o,
        "guard",
        match f.guard() {
            Guard::Down => "down",
            Guard::Up => "up",
        },
    )?;
    let statuses = Array::new();
    for st in f.statuses() {
        let so = Object::new();
        set(&so, "id", status_name(st.id))?;
        set(&so, "turns", st.turns)?;
        statuses.push(&so);
    }
    set(&o, "statuses", statuses)?;
    Ok(o)
}

fn winner_view(w: &Winner) -> Result<Object, JsError> {
    let o = Object::new();
    set(&o, "winner", side_name(w.side))?;
    set(&o, "end", end_name(w.end))?;
    set(&o, "turns", w.turns)?;
    Ok(o)
}

fn log_view(l: &TurnLog) -> Result<Object, JsError> {
    let o = Object::new();
    set(&o, "turn", l.turn)?;
    set(
        &o,
        "first",
        l.first
            .map_or(JsValue::NULL, |s| JsValue::from_str(side_name(s))),
    )?;
    let actions = Array::new();
    for a in &l.actions {
        actions.push(&action_view(a)?.into());
    }
    set(&o, "actions", actions)?;
    let events = Array::new();
    for e in &l.events {
        events.push(&event_view(e)?.into());
    }
    set(&o, "events", events)?;
    match l.end {
        Some(w) => set(&o, "end", winner_view(&w)?)?,
        None => set(&o, "end", JsValue::NULL)?,
    }
    Ok(o)
}

fn action_view(a: &ActionLog) -> Result<Object, JsError> {
    let o = Object::new();
    set(&o, "side", side_name(a.side))?;
    let played = Object::new();
    match a.played {
        Played::Move { index } => {
            set(&played, "kind", "move")?;
            set(&played, "index", index)?;
        }
        Played::Item { item, team_index } => {
            set(&played, "kind", "item")?;
            set(&played, "item", item)?;
            set(&played, "teamIndex", team_index)?;
        }
        Played::Pass => set(&played, "kind", "pass")?,
        Played::Resign => set(&played, "kind", "resign")?,
    }
    set(&o, "played", played)?;
    set(&o, "dmg", a.dmg)?;
    set(&o, "multX4", a.mult_x4)?;
    set(&o, "status", a.status.map_or(JsValue::NULL, status_name))?;
    set(&o, "burn", a.burn)?;
    set(
        &o,
        "acted",
        match a.acted {
            Acted::Acted => "acted",
            Acted::Held => "held",
        },
    )?;
    Ok(o)
}

fn event_view(e: &Event) -> Result<Object, JsError> {
    let o = Object::new();
    set(&o, "side", side_name(e.side))?;
    set(
        &o,
        "kind",
        match e.kind {
            EventKind::Faint => "faint",
            EventKind::Switch => "switch",
        },
    )?;
    set(&o, "teamIndex", e.team_index)?;
    Ok(o)
}

fn side_arg(side: &str) -> Result<Side, JsError> {
    match side {
        "a" => Ok(Side::A),
        "b" => Ok(Side::B),
        other => Err(fail(format!("a side is 'a' or 'b', not {other:?}"))),
    }
}

fn salt_arg(salt: &[u8]) -> Result<[u8; 32], JsError> {
    salt.try_into()
        .map_err(|e| fail(format!("a salt is 32 bytes: {e}")))
}

/// `H(DSM/escrow/move-commit/v1 ‖ salt ‖ u32be(|move|) ‖ move)`.
#[wasm_bindgen(js_name = moveCommitment)]
pub fn move_commitment(salt: &[u8], played: &[u8]) -> Result<Uint8Array, JsError> {
    Ok(u8a(&wildstate_duel::transcript::move_commitment(
        &salt_arg(salt)?,
        played,
    )))
}

/// Transcript entry `index` (DSM class 0x0068): `side` commits to `played`
/// under `salt`.
#[wasm_bindgen(js_name = commitEntry)]
pub fn commit_entry(
    index: u32,
    side: &str,
    salt: &[u8],
    played: &[u8],
) -> Result<Uint8Array, JsError> {
    let bytes =
        wildstate_duel::transcript::commit_entry(index, side_arg(side)?, &salt_arg(salt)?, played)
            .map_err(fail)?;
    Ok(u8a(&bytes))
}

/// Transcript entry `index`: `side` opens the move it committed to under `salt`.
#[wasm_bindgen(js_name = revealEntry)]
pub fn reveal_entry(
    index: u32,
    side: &str,
    salt: &[u8],
    played: &[u8],
) -> Result<Uint8Array, JsError> {
    let bytes =
        wildstate_duel::transcript::reveal_entry(index, side_arg(side)?, &salt_arg(salt)?, played)
            .map_err(fail)?;
    Ok(u8a(&bytes))
}

/// Transcript entry `index`: `side` resigns.
#[wasm_bindgen(js_name = resignEntry)]
pub fn resign_entry(index: u32, side: &str) -> Result<Uint8Array, JsError> {
    let bytes = wildstate_duel::transcript::resign_entry(index, side_arg(side)?).map_err(fail)?;
    Ok(u8a(&bytes))
}

/// The canonical bytes of one creature's state, `{ anchor, species, xp, hp,
/// charges }` (charges one per move of the species, in table order).
#[wasm_bindgen(js_name = encodeCreatureState)]
pub fn encode_creature_state(c: JsValue) -> Result<Uint8Array, JsError> {
    Ok(u8a(&creature_of(&c)?.encode()))
}

/// A creature's published state record: `parent` the digest of the record
/// before it, or `null` for the record it was issued with.
#[wasm_bindgen(js_name = creatureRecord)]
pub fn creature_record(parent: JsValue, state: &[u8]) -> Result<Uint8Array, JsError> {
    let parent = if parent.is_null() || parent.is_undefined() {
        None
    } else {
        let bytes = bytes_of(&parent, "parent")?;
        Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| fail(format!("parent: {e}")))?)
    };
    let record = CreatureRecordV1 {
        parent,
        state: CreatureStateV1::decode(state).map_err(fail)?,
    };
    Ok(u8a(&record.encode()))
}

/// The digest a successor names a record by.
#[wasm_bindgen(js_name = creatureRecordDigest)]
pub fn creature_record_digest(record: &[u8]) -> Result<Uint8Array, JsError> {
    Ok(u8a(&CreatureRecordV1::decode(record)
        .map_err(fail)?
        .digest()))
}

/// The latest state of creature `anchor` among its issuer's published
/// records: `{ state, digest }`, the tip of the one chain from issuance.
#[wasm_bindgen(js_name = latestCreatureState)]
pub fn latest_creature_state(anchor: &[u8], records: Array) -> Result<JsValue, JsError> {
    let anchor: [u8; 32] = anchor
        .try_into()
        .map_err(|e| fail(format!("an anchor is 32 bytes: {e}")))?;
    let mut published = Vec::new();
    for (i, r) in records.iter().enumerate() {
        published.push(bytes_of(&r, &format!("records[{i}]"))?);
    }
    let (state, digest) = wildstate_duel::creatures::latest(&anchor, &published).map_err(fail)?;
    let o = Object::new();
    set(&o, "state", u8a(&state.encode()))?;
    set(&o, "digest", u8a(&digest))?;
    Ok(o.into())
}
