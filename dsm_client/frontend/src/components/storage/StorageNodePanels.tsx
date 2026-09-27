// SPDX-License-Identifier: MIT OR Apache-2.0

// Storage panels: the pinned storage set this device's traffic uses, and what
// each member answered for its latest ByteCommit (SDK `storage.status`).
// Rendering only. A member's answer is an observation, never a verdict: a
// member that did not answer has not failed, and a ByteCommit is shown as the
// member stated it.

import React, { useState } from "react";
import type { StorageMember, StorageStatus } from "../../dsm/types";
import { middleTruncate } from "../common/ScreenFrame";

export function formatBytes(n: bigint): string {
  const v = Number(n);
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** A member answered when its node returned a ByteCommit or said it has none. */
function answered(m: StorageMember): boolean {
  return m.answer.kind !== "unanswered";
}

/** The node that answered echoed a member id other than the one the set names there. */
function answeredAsAnother(m: StorageMember): boolean {
  return m.answeredAs !== undefined && m.answeredAs !== m.memberId;
}

// ═══════════════════════════════════════════════════════════════════════
// StorageSetPanel — the set, this device's syncs and its database
// ═══════════════════════════════════════════════════════════════════════
export const StorageSetPanel: React.FC<{ status: StorageStatus }> = ({ status }) => {
  const answeredCount = status.members.filter(answered).length;
  return (
    <>
      <section className="sb-card sb-card--dark" aria-label="Storage set status">
        <div className="sb-stats">
          <div className="sb-stats__cell">
            <div className="sb-stats__val">{answeredCount}/{status.members.length}</div>
            <div className="sb-stats__label">Answered</div>
          </div>
          <div className="sb-stats__cell">
            <div className="sb-stats__val">{status.completedSyncs.toString()}</div>
            <div className="sb-stats__label">Syncs</div>
          </div>
          <div className="sb-stats__cell">
            <div className="sb-stats__val sb-stats__val--sm">{formatBytes(status.databaseBytes)}</div>
            <div className="sb-stats__label">Local DB</div>
          </div>
        </div>
      </section>

      <section className="sb-card">
        <div className="sb-kv">
          <span className="sb-kv__k">Network</span>
          <span className="sb-kv__v">{status.networkId}</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Storage set</span>
          <span className="sb-kv__v sb-kv__v--mono" title={status.storageSetIdB32}>
            {middleTruncate(status.storageSetIdB32, 12, 8)}
          </span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Members</span>
          <span className="sb-kv__v">{status.members.length}</span>
        </div>
      </section>
    </>
  );
};

// ═══════════════════════════════════════════════════════════════════════
// StorageMembersPanel — each member and its latest ByteCommit, as stated
// ═══════════════════════════════════════════════════════════════════════
export const StorageMembersPanel: React.FC<{ members: StorageMember[] }> = ({ members }) => {
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <section className="sb-card" aria-label="Storage members">
      <div className="sb-card__title">
        <span>Member</span>
        <span>Cycle · Used</span>
      </div>
      {members.map((m) => {
        const isExp = expanded === m.memberId;
        const mismatch = answeredAsAnother(m);
        const dotClass = !answered(m)
          ? "sb-dot"
          : mismatch
            ? "sb-dot sb-dot--warn"
            : "sb-dot sb-dot--on";
        const toggle = () => setExpanded(isExp ? null : m.memberId);
        return (
          <React.Fragment key={m.memberId}>
            <div
              className={`sb-row sb-row--tap${isExp ? " is-open" : ""}`}
              role="button"
              tabIndex={0}
              aria-expanded={isExp}
              onClick={toggle}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggle();
                }
              }}
            >
              <span className="sb-row__lead"><span className={dotClass} aria-hidden="true" /></span>
              <div className="sb-row__main">
                <div className="sb-row__title">{m.memberId}</div>
              </div>
              <span className="sb-row__amount">
                {m.answer.kind === "latest" ? m.answer.cycle.toString() : "—"}
              </span>
              <span className="sb-row__amount">
                {m.answer.kind === "latest" ? formatBytes(m.answer.bytesUsed) : "—"}
              </span>
              <span className="sb-row__chev" aria-hidden="true">{isExp ? "▾" : "›"}</span>
            </div>
            {isExp && <MemberDetail member={m} />}
          </React.Fragment>
        );
      })}
    </section>
  );
};

const MemberDetail: React.FC<{ member: StorageMember }> = ({ member: m }) => (
  <div className="sb-row__detail">
    <div className="sb-kv">
      <span className="sb-kv__k">Endpoint</span>
      <span className="sb-kv__v sb-kv__v--mono">{m.endpoint}</span>
    </div>
    <div className="sb-kv">
      <span className="sb-kv__k">Incarnation</span>
      <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(m.registerIncarnationB32, 8, 6)}</span>
    </div>
    {m.answer.kind === "latest" && (
      <>
        <div className="sb-kv">
          <span className="sb-kv__k">Root</span>
          <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(m.answer.rootB32, 8, 6)}</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Digest</span>
          <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(m.answer.digestB32, 8, 6)}</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Parent</span>
          <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(m.answer.parentB32, 8, 6)}</span>
        </div>
      </>
    )}
    {m.answer.kind === "noCycle" && (
      <p className="sb-hint sb-hint--tight">States it has closed no cycle yet.</p>
    )}
    {m.answer.kind === "unanswered" && (
      <p className="sb-hint sb-hint--tight">{m.answer.why}</p>
    )}
    {m.answeredAs === undefined && answered(m) && (
      <p className="sb-hint sb-hint--tight">The node that answered named no member.</p>
    )}
    {answeredAsAnother(m) && (
      <p className="sb-hint sb-hint--tight"><span className="sb-tag">Answered as {m.answeredAs}.</span></p>
    )}
  </div>
);
