/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo, useCallback } from 'react';
import { launchDeTFi, parseDeTFiHeader } from '../../dsm/detfi';
import { useDpadNav } from '../../hooks/useDpadNav';
import './SettingsScreen.css';

// Pre-compiled example blobs from examples/detfi/compiled/
const EXAMPLE_BLOBS = [
  {
    label: 'Simple Escrow (posted)',
    blob: '040G02H00000000000000000000000000000000000000000000000000001480000000000000000000000000000000000000000000000000000D20A5AKJHPJPEMAWPPV1C7AJ8X0KXTW86N5QJZNCGQH2498X5DVX9348G6JEQVRAAYEFX6JZ1XC3T77XNJFYNJ3H4Q0SHPWJDRXC11KRNAHX0',
  },
  {
    label: 'Bitcoin-backed Vault',
    blob: '040G02H00000000000000000000000000000000000000000000000000001480000000000000000000000000000000000000000000000000000D21PVR9CTBG9EARX1KC0N3ASR5E64E9JGVZQT3TZ792VY6WARY7RGZ48G568BW53P9EFZR666R55Z85SCH7XJ9YAA1S9H2TMG3K6Q2P7MXT9R',
  },
  {
    label: 'Stablecoin Policy',
    blob: '040G22QM11Q62VB578G56X31C9P6ARVFD5Q58WK1DSSPCSBJA1QPRTB3F457CSBJEDMPYVHT40RJWC1E60568SBKCDS6JW3MD5QPWEH08D858G90CSQQ483JCNKQAV31EHJP883KEHGP4V35CDQPJVH0EXMQ8T10CDQPTW3CD5GPWRV541KQARBJCHS62TBCEC574XBCCNSKM2HD41Q62VB578G6MXBJD5SP8TB3EHMPYVJZC9P6YRVB18G20RVFDSJ6JX39DXQ3M2H040G20RVFDSJ6JX39DXQ5YX3SE1JKM832DHGP6TVCD5SQ82H040G20W31E9GPTSBMCNS76EGA40G2081041HPGSB3DDFQ8YBGCMX20WV5DSJ6AWJZC5Q68QVJCNHPJW39CNQ782H040G20810D9TQ4TBKCHMP6X39DXQ76EH0AD0MWGTM957MWHA4BX0JRMT19S1N8JAF9S2M8QT25H9M2KJ3AH4MYKJ58HFM62H041GP6X39DXQ3M2H040G20X3SE1JKM834CNQ7J2H041R74TBFE9MQ8Y9T40SK0C0A5MG6WRBDCMX20T39CXM5YXK1DHTPAQVJCNV6JSBQ18G20RVFDSJ6JX39DXQ3M2H040G20RVFDSJ6JX39DXQ5YX3SE1JKM83KD5KPWRBMENS6AQVJCNRQATBJCNJ0M81040G70RBJC5PPAX35E9SKM2H040G20810CDQQAVKM78G2ECH718G2081040G74SB1EDQPWEH0CDQPTW3CD5GPWRV5BXS6AXK9CNVGM81040G2083MD1S6AWV8DXP68QV1DNQQAVKM78G2ED9G60R309RA40G62RVMD5QPWEGA40G2083MF5R6AEH0E9JQ2XB9E9JNYRBGE1S6YXK1DG52083GE9MPYWK9EHWKM81J60R0MB90DSGPTS9T41SQ8RBECHGQ4S2ZEHS62VKKCSJQ4QVCD5PPJX0A40G66VVECHMQ8TBFDRX0M81040G66VVECHMQ8TBFDSFQ8YBGCMX20RBDDXTPWX2ZDHMPTTBM18G20810E1GQ4RBDCNT6AWKK7852081040G20RVNE9S6AVK3F4X20H2K9M52081040G20VB1F1FP2VBFENQ78EH04WRK0C1G60KGM81040G2083QD5Q68VVQBXMQ8SBJC5T6JVVEECX209SR6RT30C1718G20RB3EHMPYVHT18G20810EHWQ0S9T41GPRV3FEW52083GE9MPYWK9EHWKM81H60R0MB90DSGPTS9T41QPCSJZD1QQAWKKBXJ6AV31F4520833DXQ68TBMD5QPWEGA40G20833DXQ68TBMD5QPWQVMF5R6AEH0D5T6AWK1EHMPYVJZEXMPWS3FEW52081041R62WK1DNJQ8SBJECX0M81040G20831DNQQAVKMBXT6GWK5EDM6YV3478G2ED9G60R2E2H040G20810CNQ68QV9EHJQ4RBMD5QPWEH04WS3GC1G60KGM81040G2083KEHGQ4X2ZD5T6AWK1EHMPYVHT40KK4CHG60R2E2H041GP6X39DXQ3M2H040G20X3SE1JKM834CNP62Y8A40G20839EHJQ4RBMD5QPWWST40RK8D1G6052083GE9MPYWK9EHWKM81Q6M56TSBMC5J62X3178520833DXPQ0V39C5Q66SAZCSS62VB5EXQQ4TST41256KAZ8D35YXHJ5RRGM810D5SQ6XB5E8X20H2K9NFMCVVNDSJ62X39DXQ0M810E1GQ8X35E9Q3M83KEHGP4V35CDQPJVJZCDQPTW3CD5GPWRV518',
  },
];

export default function DevDeTfiLaunchScreen(): JSX.Element {
  const [blobBase32, setBlobBase32] = useState('');
  const [status, setStatus] = useState<string>('');
  const [exampleIdx, setExampleIdx] = useState(0);

  // Parse header whenever blob changes
  const headerPreview = useMemo(() => {
    if (!blobBase32.trim()) return null;
    return parseDeTFiHeader(blobBase32);
  }, [blobBase32]);

  const pasteFromClipboard = async () => {
    try {
      if (!navigator?.clipboard?.readText) {
        setStatus('Clipboard API unavailable; paste manually.');
        return;
      }
      const txt = await navigator.clipboard.readText();
      if (!txt) {
        setStatus('Clipboard empty');
        return;
      }
      setBlobBase32(txt.trim());
      setStatus('Pasted from clipboard');
    } catch (e: any) {
      setStatus(e?.message || 'Clipboard read failed');
    }
  };

  const handleLaunch = async () => {
    setStatus('');
    try {
      const out = await launchDeTFi(blobBase32);
      if (out?.success) {
        const parts = [`Launched: ${out.type ?? 'unknown'}`];
        if (out.mode) parts.push(`mode=${out.mode}`);
        if (out.id) parts.push(`id=${out.id}`);
        setStatus(parts.join(' | '));
      } else {
        setStatus(`Launch failed: ${out?.error ?? 'unknown'}`);
      }
    } catch (e: any) {
      setStatus(e?.message || 'DeTFi launch failed');
    }
  };

  const loadExample = () => {
    const example = EXAMPLE_BLOBS[exampleIdx % EXAMPLE_BLOBS.length];
    setBlobBase32(example.blob);
    setStatus(`Loaded: ${example.label}`);
    setExampleIdx((exampleIdx + 1) % EXAMPLE_BLOBS.length);
  };

  const onSelect = useCallback((idx: number) => {
    if (idx === 0) {
      void handleLaunch();
      return;
    }
    if (idx === 1) {
      loadExample();
      return;
    }
    if (idx === 2) {
      void pasteFromClipboard();
    }
  }, [handleLaunch, loadExample, pasteFromClipboard]);

  const { focusedIndex } = useDpadNav({
    itemCount: 3,
    onSelect,
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="settings-shell settings-shell--dev">
      <div className="settings-shell__title">DeTFi Launch</div>

      <div className="settings-shell__panel">
        <div style={{ fontSize: 10, color: 'var(--text-disabled)' }}>
          Paste a compiled DeTFi spec (Base32 blob from dsm-gen compile).
          The app will decode the header, fill in your device identity,
          create the vault or publish the policy, and return the result.
        </div>
      </div>

      <div className="settings-shell__stack">
        <textarea
          rows={4}
          value={blobBase32}
          onChange={(e) => setBlobBase32(e.target.value)}
          placeholder="Base32 DeTFi spec blob..."
          style={{
            width: '100%',
            fontFamily: 'monospace',
            fontSize: 10,
            background: 'var(--bg)',
            color: 'var(--text-dark)',
            border: '1px solid var(--border)',
            padding: 4,
            resize: 'vertical',
          }}
        />

        {blobBase32.trim() && headerPreview && (
          <div
            style={{
              fontSize: 10,
              padding: '4px 0',
              color: headerPreview.success
                ? 'var(--text-dark)'
                : 'var(--text-disabled)',
            }}
          >
            {headerPreview.success && headerPreview.header
              ? `Type: ${headerPreview.header.type} | Mode: ${headerPreview.header.mode} | Size: ${headerPreview.header.sizeBytes} bytes`
              : `Header error: ${headerPreview.error}`}
          </div>
        )}

        <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
          <button
            className={`settings-shell__button${fc(0)}`}
            onClick={() => void handleLaunch()}
            style={{ flex: 1 }}
          >
            LAUNCH DETFI
          </button>
          <button
            className={`settings-shell__button${fc(1)}`}
            onClick={() => loadExample()}
            style={{ flex: 1 }}
          >
            LOAD EXAMPLE
          </button>
          <button
            className={`settings-shell__button${fc(2)}`}
            onClick={() => void pasteFromClipboard()}
            style={{ flex: 1 }}
          >
            PASTE FROM CLIPBOARD
          </button>
        </div>

        {status && (
          <div
            role="status"
            aria-live="polite"
            style={{
              fontSize: 10,
              marginTop: 4,
              color: 'var(--text-dark)',
              wordBreak: 'break-all',
            }}
          >
            {status.toUpperCase()}
          </div>
        )}
      </div>

      <div className="settings-shell__hint">Press B to go back</div>
    </div>
  );
}
