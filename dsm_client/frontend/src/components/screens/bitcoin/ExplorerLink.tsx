// SPDX-License-Identifier: Apache-2.0
// A mempool.space link the WebView cannot open, so a tap copies it instead.
import React from 'react';

type Props = {
  url: string;
  label?: string;
  onCopied: () => void;
  onCopyFailed: (url: string) => void;
};

export default function ExplorerLink({ url, label, onCopied, onCopyFailed }: Props): React.JSX.Element {
  const copy = () => {
    navigator.clipboard.writeText(url).then(onCopied, () => onCopyFailed(url));
  };
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={(e) => { e.stopPropagation(); copy(); }}
      onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); copy(); } }}
      className="sb-mono"
      style={{ marginTop: 6, fontSize: 9, textDecoration: 'underline', cursor: 'copy', padding: '2px 0', color: 'var(--text-dark)' }}
      title="Tap to copy the explorer link"
    >
      {label ? `${label}: ` : ''}{url}
    </div>
  );
}
