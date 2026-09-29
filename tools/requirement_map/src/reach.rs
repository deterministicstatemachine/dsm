// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reachability from one production artifact's entry points, in three values:
//!
//! - Reached: a path of proven edges leads from an entry point to it. A
//!   `trait-dispatch` step, or a `self-type` step (an impl of an outside
//!   trait), counts only with evidence the impl can run: for a method taking
//!   `self`, reached code constructs a value of the `Self` type; for an
//!   associated function (no `self`), reached code dispatches on the type (a
//!   call's type argument, a qualified path, or an associated item of the
//!   type reached). A value of the type is no evidence that an associated
//!   function is dispatched on it. A type merely named (in a signature, a
//!   bound, an annotation) is neither.
//!
//!   Reached by proven references alone is `REACHED`. Reached only through
//!   at least one dispatch step is `REACHED_VIA_DISPATCH`: the impl can run
//!   where a value or type the evidence names reaches the dispatching call,
//!   which the index does not show.
//! - Indeterminate: no proven path, but an uncertain step could lead to it (an
//!   uncertain edge, a dispatch whose `Self` type is not established, or a
//!   seed: something the index cannot see names it).
//! - Dead: neither.
//!
//! False Reached is the outcome this must never produce; uncertainty is always
//! Indeterminate.

use std::collections::{BTreeMap, HashSet, VecDeque};

pub const TRAIT_DISPATCH: &str = "trait-dispatch";
/// A reference that makes a value of the type it names.
pub const CONSTRUCT: &str = "construct";
/// A member that runs on or reads a value (a method taking `self`, a field)
/// reaches its type: reaching it means a value of the type exists.
pub const MEMBER_OF: &str = "member-of";
/// An associated function or constant reaches its type: the type is
/// resolved, but no value of it need exist.
pub const ASSOCIATED_OF: &str = "associated-of";
/// A reference that dispatches on a type without a value: a call's type
/// argument (`f::<T>()`) or a qualified path's self type (`<T as Trait>::f()`).
pub const TYPE_ARGUMENT: &str = "type-argument";
/// An impl of an outside trait (`Drop`, `Display`, `From` through `?`) runs
/// wherever a value of its `Self` type is used.
pub const SELF_TYPE: &str = "self-type";

/// Stable codes for each state and each reason a node is not Reached. Tools
/// and agents read these; the text beside each says it for a person.
pub mod code {
    /// A path of proven references, with no dispatch step, from an entry point.
    pub const REACHED: &str = "REACHED";
    /// Reached only through at least one `trait-dispatch` or `self-type` step
    /// whose evidence (a constructed value, a type dispatched on) is reached.
    pub const REACHED_VIA_DISPATCH: &str = "REACHED_VIA_DISPATCH";
    /// A reached call through a trait could run the impl, but reached code
    /// constructs no value of its `Self` type.
    pub const DISPATCH_SELF_TYPE: &str = "IND_DISPATCH_SELF_TYPE";
    /// A method of an outside trait's impl on a type reached code names but
    /// never constructs.
    pub const NOT_CONSTRUCTED: &str = "IND_NOT_CONSTRUCTED";
    /// An associated function of an outside trait's impl (`From::from`,
    /// `Default::default`) on a type reached code never dispatches on by
    /// type: the call is implicit (`?`, `into()`) or through a bound, which
    /// the index does not show.
    pub const NOT_DISPATCHED: &str = "IND_NOT_DISPATCHED";
    /// The impl's trait name matches several traits and the file does not decide.
    pub const AMBIGUOUS_TRAIT: &str = "IND_AMBIGUOUS_TRAIT";
    /// A type name that matches several types.
    pub const AMBIGUOUS_SELF_TYPE: &str = "IND_AMBIGUOUS_SELF_TYPE";
    /// An impl of an outside trait on a type the index holds no symbol for.
    pub const UNLINKED_IMPL: &str = "IND_UNLINKED_IMPL";
    /// A reference inside one macro invocation that writes several items.
    pub const MACRO_GROUP: &str = "IND_MACRO_GROUP";
    /// A symbol several block items share, referenced where scope does not decide.
    pub const SCOPE_UNDECIDED: &str = "IND_SCOPE_UNDECIDED";
    /// A name in call position in reached code that the index did not resolve.
    pub const UNRESOLVED_CALL: &str = "IND_UNRESOLVED_CALL";
    /// Named in the body of a reached `macro_rules!`, which the index does not expand.
    pub const MACRO_BODY: &str = "IND_MACRO_BODY";
    /// Named by a shipped artifact's source that this map could not index.
    pub const UNINDEXED_ARTIFACT: &str = "IND_UNINDEXED_ARTIFACT";
    /// Inside a `cfg` that names a feature the index enabled and the artifact
    /// does not, with a condition this map does not evaluate.
    pub const CFG_UNDECIDED: &str = "IND_CFG_UNDECIDED";
    /// An export a native declaration this map cannot spell could be.
    pub const UNREAD_DECLARATION: &str = "IND_UNREAD_DECLARATION";
    /// The artifact's index was not built on this host.
    pub const PROFILE_NOT_BUILT: &str = "IND_PROFILE_NOT_BUILT";
    /// No path of any kind leads to it from this artifact's entry points.
    pub const DEAD_NO_ROOT_PATH: &str = "DEAD_NO_ROOT_PATH";
    /// Not compiled into this artifact at all.
    pub const NOT_IN_ARTIFACT: &str = "NOT_IN_ARTIFACT";
}

/// Why something is uncertain: a stable code and a sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Doubt {
    pub code: &'static str,
    pub text: String,
}

impl Doubt {
    pub fn new(code: &'static str, text: impl Into<String>) -> Self {
        Doubt {
            code,
            text: text.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Reached,
    Indeterminate,
    Dead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: &'static str,
    /// Why the index does not prove this edge; `None` when it does.
    pub doubt: Option<Doubt>,
    /// Where the edge is read from, `file:line`.
    pub at: String,
}

/// How a node came to its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// A production entry point of this kind.
    Root(&'static str),
    /// The edge at this index of the edge list.
    Edge(usize),
    /// Something the index cannot see names it.
    Seed(Doubt),
}

#[derive(Clone, Debug)]
pub struct Reach {
    pub state: Vec<State>,
    pub via: Vec<Option<Via>>,
    /// Why a node is Indeterminate: the uncertain step its path starts from.
    pub reason: Vec<Option<Doubt>>,
}

/// The `Self` type of an impl method a `trait-dispatch` edge leads to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfType {
    /// The type's node.
    Known(usize),
    /// Why the index cannot establish it.
    Unknown(Doubt),
}

pub type SelfTypes = BTreeMap<usize, SelfType>;

fn outgoing(n: usize, edges: &[Edge]) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new(); n];
    for (i, e) in edges.iter().enumerate() {
        out[e.from].push(i);
    }
    out
}

/// The nodes a path of proven edges reaches from `roots`, and how each was
/// reached.
pub fn reached(
    n: usize,
    edges: &[Edge],
    roots: &[(usize, &'static str)],
    self_types: &SelfTypes,
    takes_value: &HashSet<usize>,
) -> Result<Vec<Option<Via>>, String> {
    let out = outgoing(n, edges);
    let mut via: Vec<Option<Via>> = vec![None; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    // Impl methods waiting for their `Self` type, by that type's node.
    let mut waiting: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
    for &(root, kind) in roots {
        if root >= n {
            return Err(format!("root {root} is not a node"));
        }
        if via[root].is_none() {
            via[root] = Some(Via::Root(kind));
            queue.push_back(root);
        }
    }
    // Types reached code makes a value of, and types it dispatches on
    // (constructed ones included). Impls waiting on either, by type.
    let mut constructed: HashSet<usize> = HashSet::new();
    let mut resolved: HashSet<usize> = HashSet::new();
    let mut waiting_resolved: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
    let release = |list: Option<Vec<(usize, usize)>>,
                   via: &mut Vec<Option<Via>>,
                   queue: &mut VecDeque<usize>| {
        for (m, j) in list.into_iter().flatten() {
            if via[m].is_none() {
                via[m] = Some(Via::Edge(j));
                queue.push_back(m);
            }
        }
    };
    while let Some(v) = queue.pop_front() {
        for &i in &out[v] {
            let e = &edges[i];
            if e.doubt.is_some() {
                continue;
            }
            let makes_value = e.kind == CONSTRUCT || e.kind == MEMBER_OF;
            // A value is no evidence of an associated function's dispatch:
            // only the type named where a call dispatches on it is.
            let dispatches = e.kind == TYPE_ARGUMENT || e.kind == ASSOCIATED_OF;
            if makes_value && constructed.insert(e.to) {
                release(waiting.remove(&e.to), &mut via, &mut queue);
            }
            if dispatches && resolved.insert(e.to) {
                release(waiting_resolved.remove(&e.to), &mut via, &mut queue);
            }
            if via[e.to].is_some() {
                continue;
            }
            let condition = match e.kind {
                TRAIT_DISPATCH => match self_types.get(&e.to) {
                    Some(SelfType::Known(ty)) => Some(*ty),
                    // The reason travels to classify, which seeds it.
                    Some(SelfType::Unknown(..)) => continue,
                    None => {
                        return Err(format!(
                            "the trait impl node {} has no Self type recorded",
                            e.to
                        ))
                    }
                },
                SELF_TYPE => Some(e.from),
                _ => None,
            };
            let needs_value = takes_value.contains(&e.to);
            match condition {
                Some(ty) if needs_value && !constructed.contains(&ty) => {
                    waiting.entry(ty).or_default().push((e.to, i))
                }
                Some(ty) if !needs_value && !resolved.contains(&ty) => {
                    waiting_resolved.entry(ty).or_default().push((e.to, i))
                }
                _ => {
                    via[e.to] = Some(Via::Edge(i));
                    queue.push_back(e.to);
                }
            }
        }
    }
    Ok(via)
}

/// The nodes proven references reach from `roots` with no dispatch step (no
/// `trait-dispatch`, no `self-type`), and how each was reached: the part of
/// Reached that needs no evidence about values or types.
pub fn reached_directly(
    n: usize,
    edges: &[Edge],
    roots: &[(usize, &'static str)],
) -> Result<Vec<Option<Via>>, String> {
    let out = outgoing(n, edges);
    let mut via: Vec<Option<Via>> = vec![None; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    for &(root, kind) in roots {
        if root >= n {
            return Err(format!("root {root} is not a node"));
        }
        if via[root].is_none() {
            via[root] = Some(Via::Root(kind));
            queue.push_back(root);
        }
    }
    while let Some(v) = queue.pop_front() {
        for &i in &out[v] {
            let e = &edges[i];
            let dispatch_step = e.kind == TRAIT_DISPATCH || e.kind == SELF_TYPE;
            if e.doubt.is_some() || dispatch_step || via[e.to].is_some() {
                continue;
            }
            via[e.to] = Some(Via::Edge(i));
            queue.push_back(e.to);
        }
    }
    Ok(via)
}

/// Every node's state: Reached as `reached` found it; Indeterminate for what
/// an uncertain step from a Reached node, or a seed, leads to over any edge;
/// Dead for the rest. `names` label nodes in reasons.
pub fn classify(
    edges: &[Edge],
    reached: Vec<Option<Via>>,
    self_types: &SelfTypes,
    takes_value: &HashSet<usize>,
    seeds: &[(usize, Doubt)],
    names: &[&str],
) -> Result<Reach, String> {
    let n = reached.len();
    let out = outgoing(n, edges);
    let mut state: Vec<State> = reached
        .iter()
        .map(|v| match v {
            Some(_) => State::Reached,
            None => State::Dead,
        })
        .collect();
    let mut via = reached;
    let mut reason: Vec<Option<Doubt>> = vec![None; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    let name = |i: usize| -> Result<&str, String> {
        names
            .get(i)
            .copied()
            .ok_or_else(|| format!("node {i} has no name"))
    };
    for (i, e) in edges.iter().enumerate() {
        if state[e.from] != State::Reached || state[e.to] != State::Dead {
            continue;
        }
        let why = match (&e.doubt, e.kind) {
            (Some(doubt), _) => doubt.clone(),
            (None, TRAIT_DISPATCH) => match self_types.get(&e.to) {
                Some(SelfType::Known(ty)) if takes_value.contains(&e.to) => Doubt::new(
                    code::DISPATCH_SELF_TYPE,
                    format!(
                        "a reached call through the trait could run this method, but reached code constructs no {}",
                        name(*ty)?
                    ),
                ),
                Some(SelfType::Known(ty)) => Doubt::new(
                    code::DISPATCH_SELF_TYPE,
                    format!(
                        "a reached call through the trait could run this associated function, but reached code never dispatches on {}",
                        name(*ty)?
                    ),
                ),
                Some(SelfType::Unknown(why)) => why.clone(),
                None => {
                    return Err(format!("the trait impl {} has no Self type recorded", name(e.to)?))
                }
            },
            (None, SELF_TYPE) if takes_value.contains(&e.to) => Doubt::new(
                code::NOT_CONSTRUCTED,
                format!(
                    "a method of an outside trait's impl on {}, which reached code names but never constructs",
                    name(e.from)?
                ),
            ),
            (None, SELF_TYPE) => Doubt::new(
                code::NOT_DISPATCHED,
                format!(
                    "an associated function of an outside trait's impl on {} (as `?` or `into()` call `From::from`), which reached code never dispatches on by type; a value of the type is no evidence the function runs",
                    name(e.from)?
                ),
            ),
            (None, kind) => {
                return Err(format!(
                    "the proven {kind} edge {} -> {} leaves a reached node for one left unreached",
                    name(e.from)?,
                    name(e.to)?
                ))
            }
        };
        state[e.to] = State::Indeterminate;
        via[e.to] = Some(Via::Edge(i));
        reason[e.to] = Some(why);
        queue.push_back(e.to);
    }
    for (node, why) in seeds {
        let node = *node;
        if node >= n {
            return Err(format!("seed {node} is not a node"));
        }
        if state[node] == State::Dead {
            state[node] = State::Indeterminate;
            via[node] = Some(Via::Seed(why.clone()));
            reason[node] = Some(why.clone());
            queue.push_back(node);
        }
    }
    while let Some(v) = queue.pop_front() {
        for &i in &out[v] {
            let w = edges[i].to;
            if state[w] == State::Dead {
                state[w] = State::Indeterminate;
                via[w] = Some(Via::Edge(i));
                reason[w] = reason[v].clone();
                queue.push_back(w);
            }
        }
    }
    Ok(Reach { state, via, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: usize, to: usize, kind: &'static str) -> Edge {
        Edge {
            from,
            to,
            kind,
            doubt: None,
            at: format!("f.rs:{from}"),
        }
    }

    fn run(
        n: usize,
        edges: &[Edge],
        roots: &[(usize, &'static str)],
        self_types: &SelfTypes,
        seeds: &[(usize, Doubt)],
    ) -> Result<Reach, String> {
        let names: Vec<String> = (0..n).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        // Every impl a test dispatches to takes `self` unless a test says otherwise.
        let takes_value: HashSet<usize> = self_types
            .keys()
            .copied()
            .chain(edges.iter().filter(|e| e.kind == SELF_TYPE).map(|e| e.to))
            .collect();
        let via = reached(n, edges, roots, self_types, &takes_value)?;
        classify(edges, via, self_types, &takes_value, seeds, &names)
    }

    #[test]
    fn proven_references_reach_and_nothing_else_does() -> Result<(), String> {
        // 0 -> 1 -> 2; 3 is on its own.
        let edges = [edge(0, 1, "reference"), edge(1, 2, "reference")];
        let r = run(4, &edges, &[(0, "export")], &SelfTypes::new(), &[])?;
        assert_eq!(
            r.state,
            vec![State::Reached, State::Reached, State::Reached, State::Dead]
        );
        assert_eq!(r.via[0], Some(Via::Root("export")));
        assert_eq!(r.via[2], Some(Via::Edge(1)));
        Ok(())
    }

    #[test]
    fn dispatch_reaches_an_impl_only_when_its_self_type_is_reached() -> Result<(), String> {
        // 0 root calls trait method 1; impls 2 (Self type 4) and 3 (Self type 5).
        // The root constructs 4 only; 3's dispatch is not established.
        let edges = [
            edge(0, 1, "reference"),
            edge(1, 2, TRAIT_DISPATCH),
            edge(1, 3, TRAIT_DISPATCH),
            edge(0, 4, CONSTRUCT),
            edge(0, 5, "reference"),
            edge(3, 6, "reference"),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(2, SelfType::Known(4));
        self_types.insert(3, SelfType::Known(5));
        let r = run(7, &edges, &[(0, "export")], &self_types, &[])?;
        assert_eq!(r.state[2], State::Reached);
        assert_eq!(r.state[3], State::Indeterminate);
        let why = r.reason[3].clone().ok_or("no reason")?;
        assert_eq!(why.code, code::DISPATCH_SELF_TYPE);
        assert!(why.text.contains("constructs no n5"));
        // What only the undecided impl calls is undecided too, with its reason.
        assert_eq!(r.state[6], State::Indeterminate);
        assert_eq!(r.reason[6], r.reason[3]);
        // n5 is named (reached), never constructed.
        assert_eq!(r.state[5], State::Reached);
        Ok(())
    }

    #[test]
    fn a_self_type_reached_after_the_trait_call_still_counts() -> Result<(), String> {
        // The trait method is reached first; the type later, through a longer path.
        let edges = [
            edge(0, 1, "reference"),
            edge(1, 2, TRAIT_DISPATCH),
            edge(0, 5, "reference"),
            edge(5, 6, "reference"),
            edge(6, 4, CONSTRUCT),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(2, SelfType::Known(4));
        let r = run(7, &edges, &[(0, "export")], &self_types, &[])?;
        assert_eq!(r.state[2], State::Reached);
        Ok(())
    }

    #[test]
    fn an_outside_trait_impl_runs_only_for_a_constructed_type() -> Result<(), String> {
        // Type 1 is only named; type 2 is constructed. Each has a Drop impl (3, 4).
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 2, CONSTRUCT),
            edge(1, 3, SELF_TYPE),
            edge(2, 4, SELF_TYPE),
        ];
        let r = run(5, &edges, &[(0, "export")], &SelfTypes::new(), &[])?;
        assert_eq!(r.state[4], State::Reached);
        assert_eq!(r.state[3], State::Indeterminate);
        assert_eq!(
            r.reason[3].as_ref().map(|d| d.code),
            Some(code::NOT_CONSTRUCTED)
        );
        Ok(())
    }

    #[test]
    fn a_reached_member_means_its_type_has_a_value() -> Result<(), String> {
        // Reaching a method of type 2 (node 1) lets a dispatch to type 2's impl run.
        let edges = [
            edge(0, 1, "reference"),
            edge(1, 2, MEMBER_OF),
            edge(0, 3, "reference"),
            edge(3, 4, TRAIT_DISPATCH),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(4, SelfType::Known(2));
        let r = run(5, &edges, &[(0, "export")], &self_types, &[])?;
        assert_eq!(r.state[4], State::Reached);
        Ok(())
    }

    #[test]
    fn an_associated_function_runs_on_dispatch_evidence_without_a_value() -> Result<(), String> {
        // Trait method 1 is reached. Impls 3 (Self type 2) and 5 (Self type 4)
        // are associated functions. The root calls `fold::<n2>()` (a type
        // argument) and only names n4 (an annotation).
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 2, TYPE_ARGUMENT),
            edge(0, 4, "reference"),
            edge(1, 3, TRAIT_DISPATCH),
            edge(1, 5, TRAIT_DISPATCH),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(3, SelfType::Known(2));
        self_types.insert(5, SelfType::Known(4));
        let names: Vec<String> = (0..6).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let associated_only = HashSet::new();
        let via = reached(6, &edges, &[(0, "export")], &self_types, &associated_only)?;
        let r = classify(&edges, via, &self_types, &associated_only, &[], &names)?;
        assert_eq!(r.state[3], State::Reached);
        assert_eq!(r.state[5], State::Indeterminate);
        // The same impl as a method taking `self` needs a value of n2: a type
        // argument is not one.
        let method: HashSet<usize> = [3].into_iter().collect();
        let via = reached(6, &edges, &[(0, "export")], &self_types, &method)?;
        let r = classify(&edges, via, &self_types, &method, &[], &names)?;
        assert_eq!(r.state[3], State::Indeterminate);
        Ok(())
    }

    #[test]
    fn a_value_is_no_evidence_of_an_associated_function_s_dispatch() -> Result<(), String> {
        // Trait method 1 is reached; impl 3 is an associated function whose
        // Self type 2 the root only constructs; impl 5's Self type 4 is a
        // call's type argument.
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 2, CONSTRUCT),
            edge(0, 4, TYPE_ARGUMENT),
            edge(1, 3, TRAIT_DISPATCH),
            edge(1, 5, TRAIT_DISPATCH),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(3, SelfType::Known(2));
        self_types.insert(5, SelfType::Known(4));
        let names: Vec<String> = (0..6).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let associated_only = HashSet::new();
        let via = reached(6, &edges, &[(0, "export")], &self_types, &associated_only)?;
        let r = classify(&edges, via, &self_types, &associated_only, &[], &names)?;
        assert_eq!(r.state[3], State::Indeterminate);
        assert_eq!(r.state[5], State::Reached);
        Ok(())
    }

    #[test]
    fn an_outside_trait_s_associated_function_runs_only_on_a_dispatch_by_type() -> Result<(), String>
    {
        // Types 1 and 2 are named; 2 is also a call's type argument. Each has
        // an outside trait's associated function (3, 4), like `From::from`.
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 2, "reference"),
            edge(0, 2, TYPE_ARGUMENT),
            edge(1, 3, SELF_TYPE),
            edge(2, 4, SELF_TYPE),
        ];
        let self_types = SelfTypes::new();
        let names: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let associated_only = HashSet::new();
        let via = reached(5, &edges, &[(0, "export")], &self_types, &associated_only)?;
        let r = classify(&edges, via, &self_types, &associated_only, &[], &names)?;
        assert_eq!(r.state[4], State::Reached);
        assert_eq!(r.state[3], State::Indeterminate);
        assert_eq!(
            r.reason[3].as_ref().map(|d| d.code),
            Some(code::NOT_DISPATCHED)
        );
        Ok(())
    }

    #[test]
    fn an_associated_item_s_type_is_dispatched_on() -> Result<(), String> {
        // Trait method 1 is reached. Impl 3's Self type 2 is dispatched on by
        // the root naming its associated item 4 (`Type::CONST`); impl 5's
        // Self type 6 is only constructed, which is no dispatch.
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 4, "reference"),
            edge(4, 2, ASSOCIATED_OF),
            edge(0, 6, CONSTRUCT),
            edge(1, 3, TRAIT_DISPATCH),
            edge(1, 5, TRAIT_DISPATCH),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(3, SelfType::Known(2));
        self_types.insert(5, SelfType::Known(6));
        let names: Vec<String> = (0..7).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let associated_only = HashSet::new();
        let via = reached(7, &edges, &[(0, "export")], &self_types, &associated_only)?;
        let r = classify(&edges, via, &self_types, &associated_only, &[], &names)?;
        assert_eq!(r.state[3], State::Reached);
        assert_eq!(r.state[5], State::Indeterminate);
        Ok(())
    }

    #[test]
    fn a_dispatch_step_is_told_from_a_direct_path() -> Result<(), String> {
        // 0 calls trait method 1 and constructs 2; impl 3 (Self type 2) is
        // reached by dispatch, and 4 only through it. 5 is called directly.
        let edges = [
            edge(0, 1, "reference"),
            edge(0, 2, CONSTRUCT),
            edge(1, 3, TRAIT_DISPATCH),
            edge(3, 4, "reference"),
            edge(0, 5, "reference"),
        ];
        let mut self_types = SelfTypes::new();
        self_types.insert(3, SelfType::Known(2));
        let direct = reached_directly(6, &edges, &[(0, "export")])?;
        let reached_by: Vec<usize> = (0..6).filter(|&i| direct[i].is_some()).collect();
        assert_eq!(reached_by, vec![0, 1, 2, 5]);
        let r = run(6, &edges, &[(0, "export")], &self_types, &[])?;
        assert_eq!(r.state[3], State::Reached);
        assert_eq!(r.state[4], State::Reached);
        Ok(())
    }

    #[test]
    fn an_uncertain_edge_leads_only_to_indeterminate() -> Result<(), String> {
        let mut uncertain = edge(0, 1, "self-type");
        uncertain.doubt = Some(Doubt::new(
            code::AMBIGUOUS_SELF_TYPE,
            "`Error` names 3 types",
        ));
        let r = run(2, &[uncertain], &[(0, "export")], &SelfTypes::new(), &[])?;
        assert_eq!(r.state, vec![State::Reached, State::Indeterminate]);
        assert_eq!(
            r.reason[1].as_ref().map(|d| d.code),
            Some(code::AMBIGUOUS_SELF_TYPE)
        );
        Ok(())
    }

    #[test]
    fn an_unestablished_self_type_never_reaches() -> Result<(), String> {
        let edges = [edge(0, 1, "reference"), edge(1, 2, TRAIT_DISPATCH)];
        let mut self_types = SelfTypes::new();
        self_types.insert(
            2,
            SelfType::Unknown(Doubt::new(
                code::AMBIGUOUS_SELF_TYPE,
                "the impl's Self type `X` names 2 types",
            )),
        );
        let r = run(3, &edges, &[(0, "export")], &self_types, &[])?;
        assert_eq!(r.state[2], State::Indeterminate);
        assert_eq!(
            r.reason[2].as_ref().map(|d| d.code),
            Some(code::AMBIGUOUS_SELF_TYPE)
        );
        Ok(())
    }

    #[test]
    fn seeds_make_the_unreached_indeterminate_and_leave_the_reached_alone() -> Result<(), String> {
        let edges = [edge(0, 1, "reference"), edge(2, 3, "reference")];
        let seeds = vec![
            (1, Doubt::new(code::MACRO_BODY, "named by a macro body")),
            (
                2,
                Doubt::new(code::UNINDEXED_ARTIFACT, "named by an unindexed crate"),
            ),
        ];
        let r = run(5, &edges, &[(0, "export")], &SelfTypes::new(), &seeds)?;
        assert_eq!(
            r.state,
            vec![
                State::Reached,
                State::Reached,
                State::Indeterminate,
                State::Indeterminate,
                State::Dead
            ]
        );
        assert_eq!(
            r.reason[3].as_ref().map(|d| d.code),
            Some(code::UNINDEXED_ARTIFACT)
        );
        Ok(())
    }
}
