# MASTER_REQUIREMENTS

Derived artifact. Not a source of protocol truth; `specs/README.md` governs.

**Status:** Round 1 — independent extraction open. The canonical list (§8) stays empty until every extractor has finished and reconciliation (§7) has run.

Several extractors produce this list independently and the results are cross-referenced: Claude (chat), Claude Code, Gemini, and possibly ChatGPT. This file defines the one format they all use, so that their outputs can be compared mechanically rather than by reading.

---

## 1 Pinned corpus

Every extraction in this round is taken against exactly these bytes:

| File | `git hash-object` | Lines |
|---|---|---|
| `specs/DSM_High_Level_Explainer.md` | `c21b78c5a37ae0899e1cf3556fe10b0fa4e087a7` | 4296 |
| `specs/SoFi_Settlement_Specification.md` | `86bce47771a8802b20438afef52e63d64e73e174` | 2592 |
| `specs/dBTC_Native_Specification.md` | `233a3e72a5b16a023af830f4c8ffaad4ba9391a8` | 2160 |
| `specs/DSM_Storage_Node_Specification.md` | `cb30606704f33ee19db2e5c1669ff7bc6ce04d3b` | 543 |

The DSM and SoFi specifications were amended on 2026-09-22 (marked "Amendment" in their text). The storage-node specification was added to the corpus on 2026-09-22, before any other extractor started. The owner accepted it in full the same day. Extract its items marked **Open** with Flags `ambiguous` and a Requirement text that says so, never as settled requirements.

Before starting, run `git hash-object specs/DSM_High_Level_Explainer.md specs/SoFi_Settlement_Specification.md specs/dBTC_Native_Specification.md specs/DSM_Storage_Node_Specification.md`. If any hash differs, stop and tell the owner: IDs are line-based (§4), so extractions taken against different bytes cannot be cross-referenced. If the owner changes a spec mid-round, this table is updated and every extraction records which hashes it used.

## 2 Independent extractions

- Each extractor writes **only** `specs/requirements/extractions/<extractor>.md`. Slugs: `claude-chat`, `claude-code`, `gemini`, `chatgpt`.
- These per-extractor files were authorized by the owner on 2026-09-22 as inputs to this file. They are not competing requirement sources; after reconciliation this file is the only one that counts.
- **Independence:** do not open another extractor's file until your own is complete. Cross-referencing measures agreement; an extraction that has read another one measures copying.
- **Read-only otherwise.** Extraction modifies nothing but its own file: no spec edits, no code edits, no fixes. Record `git status --porcelain` before and after (CLAUDE.md, "Research agents are READ-ONLY").
- A spec problem found during extraction (conflict, tension, ambiguity) is recorded in the extraction's Findings section (§6). It is never fixed in the spec by the extractor.

## 3 What is and is not a requirement

Extract (per `specs/README.md`): invariants, required transitions, authority boundaries, evidence requirements, safety assumptions, liveness boundaries, derived theorems, and implementation obligations.

Normative force by document:

- **SoFi**: MUST / MUST NOT / MAY (§1.2); **Rule** boxes are normative; **Gate** boxes are conformance tests; **Do not** boxes are prohibitions; **Why** and **Code** boxes are not requirements.
- **dBTC**: must / must not / should / should not / may (§1.2), plus anything labelled Definition, Requirement, Invariant, Property, Assumption, or Proof Obligation. §37 (implementation mapping) is informative. §38 lists required conformance tests.
- **Amendments**: blocks marked "Amendment" in the DSM and SoFi specifications (owner, 2026-09-22) are normative. Extract them with force `explicit`.
- **DSM high-level**: has no normative-keyword convention. Requirements are the declarative statements of what the construction requires, forbids, or guarantees; definitions of state components and predicates; theorems; and statements the text itself calls protocol assumptions or implementation obligations. Most DSM entries will have force `derived` (§4).

Do not extract:

- Bitcoin Comparison / Ethereum Comparison boxes;
- worked examples (they restate a rule; cite the rule);
- deployment facts (node counts, regions, cost);
- code references and commit pins;
- historical implementation plans. The step sequencing in SoFi Part VIII is not a requirement, but a Rule box inside it is.

Take with care: **Architectural consequence** and **Tradeoff / boundary** boxes are extracted only where they state a safety assumption, a liveness boundary, or a scope limit not stated elsewhere.

Out-of-scope subsystems (emissions, recovery, dedicated offline/hardware): where an in-scope text imports one, write a single `dependency-boundary` entry saying what is imported. Do not extract the subsystem itself.

## 4 Entry format

One Markdown table row per requirement, grouped under a heading per spec section:

```
| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
```

- **ID** = `<anchor>/L<n>`.
  - `<anchor>` is the nearest section anchor at or above the quote: `<!-- spec-section: DSM-HL-… -->`, `<!-- spec-section: SOFI-… -->`, `<!-- spec-section: STOR-… -->`, or `<a id="DBTC-SPEC-…">`.
  - `<n>` is the line number of the quote in the pinned file.
  - If two requirements quote the same line, suffix `.a`, `.b` in order of appearance.
  - Text above a file's first anchor uses `DSM-PRE` or `DBTC-PRE`. (SoFi's opening section already has the anchor `SOFI-PREAMBLE`.)
  - Because IDs come from source position, two extractors who cite the same sentence produce the same ID. **The ID is the cross-reference key.**
- **Quote**: a verbatim substring of line `n`, on that single line, at least four words long, chosen so that `grep -nF -- "<quote>" specs/<file>` returns `n`. Escape `|` as `\|`.
- **Kind**: `invariant` · `transition` · `authority` · `evidence` · `safety-assumption` · `liveness-boundary` · `theorem` · `obligation` · `prohibition` · `conformance-test` · `proof-obligation` · `dependency-boundary`.
- **Force**:
  - `explicit` means the text uses a normative word or sits in a labelled box.
  - `derived` means the extractor judged declarative text to be normative. Derived entries are where extractors are expected to disagree, which is why this is recorded.
- **Requirement**: one testable sentence in the extractor's own words, written only after reading the complete source sentence or sentences.
  - It states nothing the source does not state: no added conditions, exceptions, mechanisms, parameters or examples.
  - It omits nothing that changes the meaning: every condition, alternative and exception the source states is kept.
  - If in doubt, copy the source sentence.
  - The quote check verifies only the Quote column. It does not check this column, so reconciliation reads every Requirement against its source text.
- **Attaches**:
  - For a SoFi or dBTC entry, the DSM ID it refines.
  - For a restatement inside the same document, the ID of the primary statement.
  - Otherwise `—`.
- **Flags**: `conflict(<ID>)` · `tension(<ID>)` · `ambiguous` · `figure` (the source graphic controls) · `none`.

## 5 Coverage ledger

Every extraction ends with a coverage table listing **every anchor of all four files in document order**:

```
| Anchor | Line | Title | Status |
```

Status is one of:

- `extracted (n)`
- `restated-only` (with the primary IDs)
- `no-normative-content: <reason>`
- `excluded: <category from §3>`
- `not-read`

A partial extraction is fine. An unmarked gap is not. Coverage is how a section that one extractor skipped and another mined gets caught.

Generate the anchor list with:

```
awk '/spec-section:/{match($0,/spec-section: [A-Z0-9-]+/);a=substr($0,RSTART+14,RLENGTH-14);l=FNR;w=1;next} w&&/^#/{t=$0;sub(/^#+ */,"",t);print "| " a " | " l " | " t " | not-read |";w=0}' specs/DSM_High_Level_Explainer.md specs/SoFi_Settlement_Specification.md specs/DSM_Storage_Node_Specification.md
awk '/<a id="DBTC-SPEC/{match($0,/DBTC-SPEC[A-Z0-9-]*/);a=substr($0,RSTART,RLENGTH);l=FNR;w=1;next} w&&/^#/{t=$0;sub(/^#+ */,"",t);print "| " a " | " l " | " t " | not-read |";w=0}' specs/dBTC_Native_Specification.md
```

## 6 Findings section

Each extraction also has a Findings table:

```
| # | Type | IDs | Finding |
```

- Type is `conflict`, `tension`, `ambiguity`, or `scope`.
- Per `specs/README.md`, a specification conflict is resolved by the owner **before** any code changes.

## 7 Reconciliation (after all extractions are complete)

1. **Exact match** — same ID across extractors.
2. **Near match** — same anchor, lines within ±3, same kind. The reconciler judges these, and they are never auto-merged.
3. **Canonical IDs** `MR-DSM-nnnn`, `MR-SOFI-nnnn`, `MR-DBTC-nnnn` are assigned in document order. Each canonical row lists its source IDs and which extractors found it (for example `4/4`, `2/4: claude-code, gemini`).
4. **Single-extractor entries** are reviewed individually, never dropped by vote. A lone finding may be the correct one.
5. **Disagreements** on kind, force, scope, or attachment go to a Disputes table for the owner.
6. **Coverage disagreements** (one extractor marks a section `no-normative-content` while another extracted from it) are reviewed section by section.
7. **Findings** from all extractors are merged, de-duplicated by the IDs they cite, and handed to the owner before `CONFORMANCE_GAPS.md` work starts.

## 8 Canonical requirements

*Empty until reconciliation.*
