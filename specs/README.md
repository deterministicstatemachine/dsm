# DSM Specification Folder

This folder is the authoritative engineering source for the DSM protocol architecture currently in scope. Specifications are kept as ordinary Markdown (`.md`) files so they are easy to diff, search, cite, and convert into implementation requirements.

## Current normative scope

For the current architecture and checklist round, the authoritative specification corpus contains **only these four documents**:

```text
specs/
├── README.md
├── DSM_High_Level_Explainer.md
├── SoFi_Settlement_Specification.md
├── dBTC_Native_Specification.md
├── DSM_Storage_Node_Specification.md
└── requirements/
    ├── MASTER_REQUIREMENTS.md
    ├── CONFORMANCE_GAPS.md
    └── VERIFICATION_MATRIX.md
```

- **`DSM_High_Level_Explainer.md`** is the **overarching DSM architectural specification**. It defines the common state model, invariants, acceptance structure, authority boundaries, safety assumptions, liveness boundaries, and protocol concepts that subsystem specifications refine.
- **`SoFi_Settlement_Specification.md`** is the normative subsystem specification for Sovereign Finance, DLV settlement, vault execution, routing, and the SoFi-specific authority and evidence flow.
- **`dBTC_Native_Specification.md`** is the normative subsystem specification for DSM-native Bitcoin-backed state, origin admission, dBTC transfer, withdrawal burns, DLV fulfillment, constrained Bitcoin execution, and successor vaults.
- **`DSM_Storage_Node_Specification.md`** is the normative subsystem specification for storage nodes: the storage contract, keyed cells and finality, storage sets and roles, member succession and loss, the operator registry, and storage economics. Items it marks **Open** are undecided and are not requirements.

Emissions, recovery, and dedicated offline/hardware subsystems are **out of scope for this round**. If one of the three current specifications imports such machinery as substrate, record the dependency boundary only; do not expand the current checklist into a full audit of that subsystem.

Storage-node requirements are defined by `DSM_Storage_Node_Specification.md`, which refines the DSM storage architecture and states the storage contract SoFi and dBTC rely on. Extract its **Open** items as open questions, never as requirements.

## Specification hierarchy

The hierarchy is:

```text
DSM_High_Level_Explainer.md
        ↓
SoFi_Settlement_Specification.md
 dBTC_Native_Specification.md
 DSM_Storage_Node_Specification.md
        ↓
derived requirements / conformance work
        ↓
implementation
```

The DSM high-level specification governs the common architecture. The SoFi and dBTC specifications refine that architecture for their respective subsystems. A subsystem specification may make a DSM rule more concrete, but it must not silently redefine the overarching architecture.

If two specifications appear to conflict, flag and resolve the specification conflict **before changing code**.

## Required derived artifacts

The `specs/requirements/` subtree is **mandatory for this round**. Do not create competing requirement, gap, audit, or verification files elsewhere unless the owner explicitly authorizes it.

Required files:

- **`specs/requirements/MASTER_REQUIREMENTS.md`** — requirements extracted from the four authoritative specifications.
- **`specs/requirements/CONFORMANCE_GAPS.md`** — comparison of those requirements against the real backend: missing mechanisms, wrong authority boundaries, stand-ins, partial skeletons, obsolete code, and conformance status.
- **`specs/requirements/VERIFICATION_MATRIX.md`** — maps security-critical requirements to implementation loci, tests, mutation controls, and formal artifacts where applicable.

These files are derived artifacts. They are **not independent sources of protocol truth**.

The repository is evidence of implementation state, **not evidence of protocol intent**. Existing code may satisfy, violate, partially implement, or be unrelated to a requirement; it does not create a normative requirement by itself.

## Agent instruction files

Repository-wide agent operating instructions live at the repository root:

```text
CLAUDE.md
AGENTS.md
```

These files contain operating instructions only: how agents should work, which specifications to read, how to handle conflicts, and where derived artifacts belong.

Do **not** place protocol specifications in `.instructions.md`, `CLAUDE.md`, or `AGENTS.md`. Protocol truth belongs in `specs/`.

## What goes where

- **`specs/*.md`** — authoritative specification text for the current protocol scope.
- **`specs/requirements/*.md`** — mandatory derived requirements, conformance, and verification artifacts.
- **`CLAUDE.md` / `AGENTS.md` at repository root** — agent operating instructions only.
- **PDFs** — publication/archive artifacts. Keep them if useful, but use the Markdown versions for engineering and checklist work.
- **Companion explainers** — supporting reader-oriented material kept outside `specs/` when a dedicated normative subsystem specification exists.

## Checklist extraction rule

Build `MASTER_REQUIREMENTS.md` from the specification corpus **before comparing against implementation**.

Extract requirements such as:

- invariants;
- required transitions;
- authority boundaries;
- evidence requirements;
- safety assumptions;
- liveness boundaries;
- derived theorems; and
- implementation obligations.

Do not convert examples, comparisons, rationale, deployment details, or historical implementation plans into normative requirements.

A subsystem requirement should refine or attach to the applicable master DSM requirement where one exists, rather than forming an unrelated parallel checklist.

## Working flow

For this round, the required flow is:

```text
DSM + SoFi + dBTC + storage-node specifications
        ↓
MASTER_REQUIREMENTS.md
        ↓
current backend comparison
        ↓
CONFORMANCE_GAPS.md
        ↓
backend skeleton refinement
        ↓
production implementation
        ↓
VERIFICATION_MATRIX.md
        ↓
executable, mutation, and formal verification
```

Before changing backend architecture, read `DSM_High_Level_Explainer.md` and every applicable current subsystem specification. Derive required behavior from those documents, not from whatever the repository currently happens to contain.

A removed stand-in does not define its replacement invariant. The applicable specification does.
