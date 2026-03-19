import React from 'react';
import { ReceiptCommit } from '../../proto/dsm_app_pb';
import { encodeBase32Crockford } from '../../utils/textId';

function toB32(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  return encodeBase32Crockford(bytes);
}

function b32Preview(bytes: Uint8Array, head = 8, tail = 8): string {
  const full = toB32(bytes);
  if (!full) return '—';
  if (full.length <= head + tail + 3) return full;
  return `${full.slice(0, head)}…${full.slice(-tail)}`;
}

type Props = {
  bytes?: Uint8Array | null;
  title?: string;
};

const labelStyle: React.CSSProperties = {
  fontSize: 9,
  color: 'var(--text-dark)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
};

const valueStyle: React.CSSProperties = {
  fontSize: 9,
  color: 'var(--text)',
  wordBreak: 'break-all',
};

const rowStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '92px 1fr',
  gap: 8,
  alignItems: 'start',
  marginTop: 6,
};

const StitchedReceiptDetails: React.FC<Props> = ({ bytes, title = 'Stitched Receipt' }) => {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    return (
      <div style={{ marginTop: 8, fontSize: 9, color: 'var(--text-dark)' }}>
        {title}: not available
      </div>
    );
  }

  const totalBytes = bytes.length;
  let decoded: ReceiptCommit;
  try {
    decoded = ReceiptCommit.fromBinary(bytes);
  } catch {
    return (
      <div style={{ marginTop: 8, fontSize: 9, color: 'var(--text-dark)' }}>
        {title}: invalid receipt bytes ({totalBytes} bytes)
      </div>
    );
  }

  const tipBytes = decoded.childTip.length > 0 ? decoded.childTip : decoded.parentTip;

  return (
    <details style={{ marginTop: 8 }}>
      <summary style={{ cursor: 'pointer', fontSize: 9, color: 'var(--text)', textTransform: 'uppercase', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <span>{title}</span>
        <span>· {totalBytes} bytes</span>
        <span>· {b32Preview(tipBytes)}</span>
      </summary>
      <div style={{ marginTop: 8, padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'rgba(var(--text-dark-rgb),0.08)' }}>
        <div style={rowStyle}>
          <span style={labelStyle}>Genesis</span>
          <span style={valueStyle}>{toB32(decoded.genesis) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Dev A</span>
          <span style={valueStyle}>{toB32(decoded.devidA) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Dev B</span>
          <span style={valueStyle}>{toB32(decoded.devidB) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Parent tip</span>
          <span style={valueStyle}>{toB32(decoded.parentTip) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Child tip</span>
          <span style={valueStyle}>{toB32(decoded.childTip) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Parent root</span>
          <span style={valueStyle}>{toB32(decoded.parentRoot) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Child root</span>
          <span style={valueStyle}>{toB32(decoded.childRoot) || '—'}</span>
        </div>
        <div style={rowStyle}>
          <span style={labelStyle}>Proof sizes</span>
          <span style={valueStyle}>
            rel_parent={decoded.relProofParent.length} · rel_child={decoded.relProofChild.length} · dev={decoded.devProof.length} · replace={decoded.relReplaceWitness.length}
          </span>
        </div>
      </div>
    </details>
  );
};

export default StitchedReceiptDetails;
