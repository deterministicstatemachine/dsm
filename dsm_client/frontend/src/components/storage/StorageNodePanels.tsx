// SPDX-License-Identifier: MIT OR Apache-2.0

// Storage panels: the pinned storage set this device's traffic uses, and what
// each member answered for its latest ByteCommit (SDK `storage.status`).
// Rendering only. A member's answer is an observation, never a verdict: a
// member that did not answer has not failed, and a ByteCommit is shown as the
// member stated it.

import React, { useState } from "react";
import type { StorageMember, StorageStatus } from "../../dsm/types";

export function formatBytes(n: bigint): string {
  const v = Number(n);
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function short(b32: string): string {
  return b32.length <= 12 ? b32 : `${b32.slice(0, 12)}…`;
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
    <div className="snd-stack">
      <div className="snd-card">
        <div className="snd-stat-grid">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {answeredCount}/{status.members.length}
            </div>
            <div className="snd-stat-label">Answered</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{status.completedSyncs.toString()}</div>
            <div className="snd-stat-label">Syncs</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val-sm">{formatBytes(status.databaseBytes)}</div>
            <div className="snd-stat-label">Local DB</div>
          </div>
        </div>
      </div>

      <div className="snd-card">
        <div className="snd-info-row">
          <span className="snd-info-label">Network</span>
          <span className="snd-info-val">{status.networkId}</span>
        </div>
        <div className="snd-info-row">
          <span className="snd-info-label">Storage set</span>
          <span className="snd-info-val snd-trunc" title={status.storageSetIdB32}>
            {short(status.storageSetIdB32)}
          </span>
        </div>
        <div className="snd-info-row">
          <span className="snd-info-label">Members</span>
          <span className="snd-info-val">{status.members.length}</span>
        </div>
      </div>

      <div className="snd-card storage-card-body">
        <div className="storage-card-copy storage-card-copy-muted">
          The set is pinned for this device&apos;s network. Syncs counts the inbox syncs
          that ran to their end on this device.
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════
// StorageMembersPanel — each member and its latest ByteCommit, as stated
// ═══════════════════════════════════════════════════════════════════════
export const StorageMembersPanel: React.FC<{ members: StorageMember[] }> = ({ members }) => {
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="snd-stack">
      <div className="snd-card snd-table">
        <div className="snd-table-header">
          <span />
          <span>Member</span>
          <span>Cycle</span>
          <span>Used</span>
        </div>
        {members.map((m) => {
          const isExp = expanded === m.memberId;
          const mismatch = answeredAsAnother(m);
          const rowClass = !answered(m)
            ? "snd-row snd-row-off"
            : mismatch
              ? "snd-row snd-row-warn"
              : "snd-row";
          const dotClass = !answered(m)
            ? "snd-dot"
            : mismatch
              ? "snd-dot snd-dot-warn"
              : "snd-dot snd-dot-on";
          return (
            <React.Fragment key={m.memberId}>
              <div
                className={`${rowClass}${isExp ? " snd-row-exp" : ""}`}
                onClick={() => setExpanded(isExp ? null : m.memberId)}
              >
                <span className={dotClass} />
                <span className="snd-name">{m.memberId}</span>
                <span className="snd-region">
                  {m.answer.kind === "latest" ? m.answer.cycle.toString() : "—"}
                </span>
                <span className="snd-ms">
                  {m.answer.kind === "latest" ? formatBytes(m.answer.bytesUsed) : "—"}
                </span>
              </div>
              {isExp && <MemberDetail member={m} />}
            </React.Fragment>
          );
        })}
      </div>

      <div className="snd-card storage-card-body">
        <div className="storage-card-copy storage-card-copy-muted">
          Each member&apos;s latest ByteCommit as that member states it. A member that did
          not answer has not failed; nothing a member answers is a verdict.
        </div>
      </div>
    </div>
  );
};

const MemberDetail: React.FC<{ member: StorageMember }> = ({ member: m }) => (
  <div className="snd-detail">
    <div className="snd-detail-url">{m.endpoint}</div>
    <div className="snd-detail-stats">
      <span>Incarnation {short(m.registerIncarnationB32)}</span>
    </div>
    {m.answer.kind === "latest" && (
      <div className="snd-detail-stats">
        <span>Root {short(m.answer.rootB32)}</span>
        <span>Digest {short(m.answer.digestB32)}</span>
        <span>Parent {short(m.answer.parentB32)}</span>
      </div>
    )}
    {m.answer.kind === "noCycle" && (
      <div className="snd-detail-err">States it has closed no cycle yet.</div>
    )}
    {m.answer.kind === "unanswered" && <div className="snd-detail-err">{m.answer.why}</div>}
    {m.answeredAs === undefined && answered(m) && (
      <div className="snd-detail-err">The node that answered named no member.</div>
    )}
    {answeredAsAnother(m) && (
      <div className="snd-detail-err">Answered as {m.answeredAs}.</div>
    )}
  </div>
);
