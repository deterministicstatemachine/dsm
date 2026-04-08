/* eslint-disable react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useMemo, useState } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import { getDbrwStatus, type DbrwStatus } from '../../dsm/dbrw';
import { exportDiagnosticsReport } from '../../services/telemetry';
import { useUX } from '../../contexts/UXContext';
import { BETA_BUG_TEMPLATE, buildGitHubIssueUrl, DSM_RELEASE_REPO_URL } from '../../utils/githubIssue';
import { bytesToBase32CrockfordPrefix } from '../../utils/textId';
import './StorageScreen.css';
import './DevCdbrwScreen.css';

function formatPrefix(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return 'N/A';
  return `${bytesToBase32CrockfordPrefix(bytes, Math.min(bytes.length, 8))}…`;
}

function formatBytes(value: number): string {
  if (!value) return '0';
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function decodeLogBytes(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return 'No persisted bridge diagnostics log captured.';
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim() || 'Bridge diagnostics log was empty.';
}

function buildCdbrwReport(status: DbrwStatus, logBytes: Uint8Array): string {
  const lines = [
    'DSM C-DBRW diagnostics report',
    `repo=${DSM_RELEASE_REPO_URL}`,
    `enrolled=${status.enrolled ? 'yes' : 'no'}`,
    `binding_key_present=${status.bindingKeyPresent ? 'yes' : 'no'}`,
    `verifier_keypair_present=${status.verifierKeypairPresent ? 'yes' : 'no'}`,
    `storage_base_dir_set=${status.storageBaseDirSet ? 'yes' : 'no'}`,
    `enrollment_revision=${status.enrollmentRevision}`,
    `arena_bytes=${status.arenaBytes}`,
    `probes=${status.probes}`,
    `steps_per_probe=${status.stepsPerProbe}`,
    `histogram_bins=${status.histogramBins}`,
    `rotation_bits=${status.rotationBits}`,
    `epsilon_intra=${status.epsilonIntra.toFixed(6)}`,
    `mean_histogram_len=${status.meanHistogramLen}`,
    `reference_anchor_prefix=${formatPrefix(status.referenceAnchorPrefix)}`,
    `binding_key_prefix=${formatPrefix(status.bindingKeyPrefix)}`,
    `verifier_public_key_prefix=${formatPrefix(status.verifierPublicKeyPrefix)}`,
    `verifier_public_key_len=${status.verifierPublicKeyLen}`,
    `storage_base_dir=${status.storageBaseDir || 'N/A'}`,
    `status_note=${status.statusNote || 'No additional note.'}`,
    `runtime_metrics_present=${status.runtimeMetricsPresent ? 'yes' : 'no'}`,
    `runtime_access_level=${status.runtimeAccessLevel || 'N/A'}`,
    `runtime_trust_score=${status.runtimeTrustScore.toFixed(6)}`,
    `runtime_health_check_ran=${status.runtimeHealthCheckRan ? 'yes' : 'no'}`,
    `runtime_health_check_passed=${status.runtimeHealthCheckPassed ? 'yes' : 'no'}`,
    `runtime_h_hat=${status.runtimeHHat.toFixed(6)}`,
    `runtime_rho_hat=${status.runtimeRhoHat.toFixed(6)}`,
    `runtime_l_hat=${status.runtimeLHat.toFixed(6)}`,
    `runtime_match_score=${status.runtimeMatchScore.toFixed(6)}`,
    `runtime_w1_distance=${status.runtimeW1Distance.toFixed(6)}`,
    `runtime_w1_threshold=${status.runtimeW1Threshold.toFixed(6)}`,
    `runtime_anchor_prefix=${formatPrefix(status.runtimeAnchorPrefix)}`,
    `runtime_error=${status.runtimeError || 'N/A'}`,
    `runtime_h0_eff=${status.runtimeH0Eff.toFixed(6)}`,
    `runtime_recommended_n=${status.runtimeRecommendedN}`,
    `runtime_resonant_status=${status.runtimeResonantStatus || 'N/A'}`,
    '',
    '--- bridge diagnostics log ---',
    decodeLogBytes(logBytes),
  ];
  return lines.join('\n');
}

export default function DevCdbrwScreen(): JSX.Element {
  const { notifyToast } = useUX();
  // Stored enrollment data (loaded on mount — instant, no heavy capture)
  const [status, setStatus] = useState<DbrwStatus | null>(null);
  // Live health data (loaded only on explicit "RUN LIVE CHECK" button press)
  const [healthStatus, setHealthStatus] = useState<DbrwStatus | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'enrollment' | 'health' | 'keys' | 'report'>('overview');
  const [loading, setLoading] = useState(true);
  const [healthLoading, setHealthLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportText, setReportText] = useState('');
  const [error, setError] = useState('');

  /** Load stored enrollment data only (fast, no heavy capture). */
  const refresh = async (): Promise<DbrwStatus | null> => {
    setLoading(true);
    setError('');
    try {
      const next = await getDbrwStatus(false);
      setStatus(next);
      return next;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setLoading(false);
    }
  };

  /** Run live health check (heavy: 9 derive trials + health capture). */
  const runLiveCheck = async (): Promise<DbrwStatus | null> => {
    setHealthLoading(true);
    setError('');
    try {
      const next = await getDbrwStatus(true);
      setHealthStatus(next);
      // Also update stored status with the latest enrollment data
      setStatus(next);
      return next;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setHealthLoading(false);
    }
  };

  const loadReport = async (snapshot?: DbrwStatus | null): Promise<string> => {
    // Prefer health snapshot (has runtime metrics) for report, fall back to stored
    const baseStatus = snapshot || healthStatus || status;
    if (!baseStatus) {
      throw new Error('Load status first before generating a report.');
    }
    setReportLoading(true);
    try {
      const logBytes = await exportDiagnosticsReport();
      const nextReport = buildCdbrwReport(baseStatus, logBytes);
      setReportText(nextReport);
      return nextReport;
    } finally {
      setReportLoading(false);
    }
  };

  // On mount: load stored enrollment data only (instant)
  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (activeTab === 'report' && !reportText && !reportLoading && (healthStatus || status)) {
      void loadReport(healthStatus || status).catch((e) => {
        setError(e instanceof Error ? e.message : String(e));
      });
    }
  }, [activeTab, reportLoading, reportText, healthStatus, status]);

  const tabList = ['overview', 'enrollment', 'health', 'keys', 'report'] as const;
  const navActions = useMemo(() => tabList.map((tab) => () => setActiveTab(tab)), []);
  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const handleRefresh = async () => {
    const next = await refresh();
    if (activeTab === 'report' && next) {
      await loadReport(healthStatus || next);
    }
  };

  const ensureReport = async (): Promise<string> => {
    if (reportText) return reportText;
    const snapshot = healthStatus || status || await refresh();
    if (!snapshot) {
      throw new Error('Unable to load C-DBRW status.');
    }
    return loadReport(snapshot);
  };

  const copyReport = async () => {
    try {
      const report = await ensureReport();
      await navigator.clipboard.writeText(report);
      notifyToast('success', 'C-DBRW report copied');
    } catch (e) {
      notifyToast('error', e instanceof Error ? e.message : 'Copy failed');
    }
  };

  const downloadReport = async () => {
    try {
      const report = await ensureReport();
      const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'dsm-cdbrw-report.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      notifyToast('success', 'C-DBRW report saved');
    } catch (e) {
      notifyToast('error', e instanceof Error ? e.message : 'Save failed');
    }
  };

  const openGitHubIssue = async () => {
    try {
      const report = await ensureReport();
      const excerpt = report.slice(0, 3000);
      const url = buildGitHubIssueUrl({
        template: BETA_BUG_TEMPLATE,
        title: 'C-DBRW diagnostics report',
        body:
          `## Summary\nPlease describe the C-DBRW problem.\n\n` +
          `## Attached Report\nDownload and attach \`dsm-cdbrw-report.txt\` from the app if possible.\n\n` +
          `## Report Excerpt\n` +
          `\`\`\`text\n${excerpt}\n\`\`\`\n`,
      });
      const popup = window.open(url, '_blank', 'noopener');
      if (!popup && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
        notifyToast('success', 'Issue link copied to clipboard');
        return;
      }
      if (!popup) {
        throw new Error('Popup blocked and clipboard unavailable.');
      }
      notifyToast('success', 'GitHub issue opened');
    } catch (e) {
      notifyToast('error', e instanceof Error ? e.message : 'Unable to open issue');
    }
  };

  const statusPillClass = status?.enrolled ? 'cdbrw-status-pill cdbrw-status-pill--ok' : 'cdbrw-status-pill cdbrw-status-pill--warn';

  // Use healthStatus for runtime metrics display (only populated after live check)
  const hs = healthStatus;

  return (
    <main className="settings-shell settings-shell--dev cdbrw-dashboard-shell" role="main" aria-labelledby="cdbrw-title">
      <div id="cdbrw-title" className="settings-shell__title">
        C-DBRW Monitor
      </div>

      <div className="settings-shell__stack cdbrw-dashboard-stage">
        <div className="storage-tab-nav">
          {tabList.map((tab, idx) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`storage-tab-button ${activeTab === tab ? 'active' : ''}${idx === focusedIndex ? ' focused' : ''}`}
            >
              {tab === 'enrollment' ? 'Enroll' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div className="snd-actions">
          <button className="snd-btn" onClick={() => void handleRefresh()}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button className="snd-btn" onClick={() => void loadReport().catch((e) => setError(e instanceof Error ? e.message : String(e)))}>
            {reportLoading ? 'Loading...' : 'Pull Logs'}
          </button>
        </div>

        {error ? (
          <div className="snd-card storage-card-body">
            <div className="snd-stat-label storage-card-title">ERROR</div>
            <div className="storage-card-copy">{error}</div>
          </div>
        ) : null}

        {activeTab === 'overview' && (
          <>
            <div className="snd-card">
              <div className="snd-stat-grid-2">
                <div className="snd-stat-cell">
                  <div className="snd-stat-val">{status?.enrolled ? 'YES' : 'NO'}</div>
                  <div className="snd-stat-label">Enrolled</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.enrolled ? 'ENFORCED' : 'BLOCKED'}</div>
                  <div className="snd-stat-label">Policy</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.bindingKeyPresent ? 'YES' : 'NO'}</div>
                  <div className="snd-stat-label">Binding</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.verifierKeypairPresent ? 'YES' : 'NO'}</div>
                  <div className="snd-stat-label">Verifier</div>
                </div>
              </div>
            </div>

            <div className="snd-card">
              <div className="snd-info-row">
                <span className="snd-info-label">Status</span>
                <span className={statusPillClass}>{status?.enrolled ? 'Ready' : 'Not Ready'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Health</span>
                <span className="snd-info-val">{hs?.runtimeMetricsPresent ? 'Live' : 'Not checked'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Access</span>
                <span className="snd-info-val">{hs?.runtimeAccessLevel || 'N/A'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Storage Dir</span>
                <span className="snd-info-val">{status?.storageBaseDirSet ? 'Configured' : 'Missing'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Trust</span>
                <span className="snd-info-val">{hs ? hs.runtimeTrustScore.toFixed(3) : 'Run health check'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Note</span>
                <span className="snd-info-val">{status?.statusNote || 'No additional note.'}</span>
              </div>
            </div>

            <div className="snd-card">
              <div className="snd-info-note">
                Enrollment data loads instantly from stored file. Use the Health tab and tap RUN LIVE CHECK for runtime entropy metrics.
              </div>
            </div>
          </>
        )}

        {activeTab === 'enrollment' && (
          <>
            <div className="snd-card">
              <div className="snd-stat-grid">
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.enrollmentRevision ?? 0}</div>
                  <div className="snd-stat-label">Rev</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{formatBytes(status?.arenaBytes ?? 0)}</div>
                  <div className="snd-stat-label">Arena</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.probes ?? 0}</div>
                  <div className="snd-stat-label">Probes</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.stepsPerProbe ?? 0}</div>
                  <div className="snd-stat-label">Steps</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.histogramBins ?? 0}</div>
                  <div className="snd-stat-label">Bins</div>
                </div>
                <div className="snd-stat-cell">
                  <div className="snd-stat-val-sm">{status?.rotationBits ?? 0}</div>
                  <div className="snd-stat-label">Rot</div>
                </div>
              </div>
            </div>

            <div className="snd-card">
              <div className="snd-info-row">
                <span className="snd-info-label">Epsilon Intra</span>
                <span className="snd-info-val">{status ? status.epsilonIntra.toFixed(6) : '0.000000'}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Mean Hist Len</span>
                <span className="snd-info-val">{status?.meanHistogramLen ?? 0}</span>
              </div>
              <div className="snd-info-row">
                <span className="snd-info-label">Storage Path</span>
                <span className="snd-info-val snd-info-val--mono">{status?.storageBaseDir || 'N/A'}</span>
              </div>
            </div>

            <div className="snd-card">
              <div className="snd-info-note">
                Stored enrollment config from initial device binding. Probes value reflects the orbit length used at enrollment time.
              </div>
            </div>
          </>
        )}

        {activeTab === 'health' && (
          <>
            <div className="snd-card storage-card-body" style={{ padding: '10px' }}>
              <button
                className="snd-btn"
                onClick={() => void runLiveCheck()}
                disabled={healthLoading}
                style={{ width: '100%', fontWeight: 'bold' }}
              >
                {healthLoading ? 'RUNNING LIVE CHECK...' : 'RUN LIVE CHECK'}
              </button>
              {healthLoading && (
                <div className="snd-info-note" style={{ textAlign: 'center', marginTop: '6px' }}>
                  Running 9 derive trials + entropy health capture. This takes a few seconds.
                </div>
              )}
            </div>

            {!hs && !healthLoading && (
              <div className="snd-card">
                <div className="snd-info-note" style={{ textAlign: 'center', padding: '16px 10px' }}>
                  Not checked. Tap RUN LIVE CHECK to run runtime entropy analysis.
                </div>
              </div>
            )}

            {hs && (
              <>
                <div className="snd-card">
                  <div className="snd-info-row">
                    <span className="snd-info-label">H hat</span>
                    <span className="snd-info-val">{hs.runtimeHHat.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">rho hat</span>
                    <span className="snd-info-val">{hs.runtimeRhoHat.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">L hat</span>
                    <span className="snd-info-val">{hs.runtimeLHat.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">h0 eff</span>
                    <span className="snd-info-val">{hs.runtimeH0Eff.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">Recommended N</span>
                    <span className="snd-info-val">{hs.runtimeRecommendedN}</span>
                  </div>
                </div>

                <div className="snd-card">
                  <div className="snd-info-row">
                    <span className="snd-info-label">W1 Drift</span>
                    <span className="snd-info-val">{hs.runtimeW1Distance.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">W1 Threshold</span>
                    <span className="snd-info-val">{hs.runtimeW1Threshold.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">Match Score</span>
                    <span className="snd-info-val">{hs.runtimeMatchScore.toFixed(6)}</span>
                  </div>
                  <div className="snd-info-row">
                    <span className="snd-info-label">Trust</span>
                    <span className="snd-info-val">{hs.runtimeTrustScore.toFixed(6)}</span>
                  </div>
                </div>

                <div className="snd-card">
                  <div className="snd-info-row">
                    <span className="snd-info-label">Health</span>
                    <span className="snd-info-val">
                      {hs.runtimeHealthCheckRan ? (
                        <span className={`cdbrw-health-pill cdbrw-health-${(hs.runtimeResonantStatus || 'unknown').toLowerCase()}`}>
                          {hs.runtimeResonantStatus || (hs.runtimeHealthCheckPassed ? 'PASS' : 'FAIL')}
                        </span>
                      ) : 'NOT RUN'}
                    </span>
                  </div>
                  {hs.runtimeHealthCheckRan && hs.runtimeResonantStatus === 'RESONANT' && (
                    <div className="snd-info-note cdbrw-health-note-resonant">
                      Thermal coupling active. Per C-DBRW Theorem 8.1(ii), temperature drift strengthens the device fingerprint by populating the chaotic attractor.
                    </div>
                  )}
                  {hs.runtimeHealthCheckRan && hs.runtimeResonantStatus === 'ADAPTED' && (
                    <div className="snd-info-note cdbrw-health-note-adapted">
                      Effective entropy rate {hs.runtimeH0Eff.toFixed(3)} below 0.5. Recommend orbit length N {'>'}= {hs.runtimeRecommendedN} per C-DBRW Remark 4.6.
                    </div>
                  )}
                  {hs.runtimeHealthCheckRan && hs.runtimeResonantStatus === 'FAIL' && (
                    <div className="snd-info-note cdbrw-health-note-fail">
                      Entropy collapsed. Investigate hardware or environmental interference.
                    </div>
                  )}
                  {hs.runtimeRecommendedN > (status?.probes ?? 0) && (status?.probes ?? 0) > 0 && (
                    <div className="snd-info-note cdbrw-health-note-adapted">
                      Device enrolled at N={status?.probes}. Health recommends N{'>'}={hs.runtimeRecommendedN} for stronger mixing. Re-enrollment with higher N available in Settings.
                    </div>
                  )}
                </div>
              </>
            )}
          </>
        )}

        {activeTab === 'keys' && (
          <div className="snd-card">
            <div className="snd-info-row">
              <span className="snd-info-label">Reference Anchor</span>
              <span className="snd-info-val snd-info-val--mono">{formatPrefix(status?.referenceAnchorPrefix ?? new Uint8Array(0))}</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Binding Key</span>
              <span className="snd-info-val snd-info-val--mono">{formatPrefix(status?.bindingKeyPrefix ?? new Uint8Array(0))}</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Verifier PK</span>
              <span className="snd-info-val snd-info-val--mono">{formatPrefix(status?.verifierPublicKeyPrefix ?? new Uint8Array(0))}</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">PK Length</span>
              <span className="snd-info-val">{status?.verifierPublicKeyLen ?? 0} bytes</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Runtime Anchor</span>
              <span className="snd-info-val snd-info-val--mono">{formatPrefix(hs?.runtimeAnchorPrefix ?? new Uint8Array(0))}</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Runtime Error</span>
              <span className="snd-info-val snd-info-val--mono">{hs?.runtimeError || 'N/A'}</span>
            </div>
          </div>
        )}

        {activeTab === 'report' && (
          <>
            <div className="snd-card storage-card-body cdbrw-report-card">
              <div className="snd-stat-label storage-card-title">REPORT ACTIONS</div>
              <div className="cdbrw-action-grid">
                <button className="snd-btn" onClick={() => void copyReport()}>
                  Copy Report
                </button>
                <button className="snd-btn" onClick={() => void downloadReport()}>
                  Save Report
                </button>
                <button className="snd-btn" onClick={() => void openGitHubIssue()}>
                  File Issue
                </button>
                <button className="snd-btn" onClick={() => void loadReport().catch((e) => setError(e instanceof Error ? e.message : String(e)))}>
                  {reportLoading ? 'Loading...' : 'Refresh Logs'}
                </button>
              </div>
              <div className="cdbrw-report-meta">
                <span>Source: Rust dbrw.status + persisted bridge log</span>
                <span>{reportText ? `${reportText.length} chars` : 'No report yet'}</span>
              </div>
            </div>

            {!hs && (
              <div className="snd-card">
                <div className="snd-info-note" style={{ textAlign: 'center' }}>
                  Report uses stored enrollment data. Run a live health check from the Health tab for full runtime metrics in the report.
                </div>
              </div>
            )}

            <div className="snd-card storage-card-body">
              <div className="snd-stat-label storage-card-title">REPORT PREVIEW</div>
              <pre className="cdbrw-report-preview">{reportText || 'Pull logs to generate a report users can copy, save, or attach to a GitHub issue.'}</pre>
            </div>
          </>
        )}
      </div>

      <div className="settings-shell__hint">Press B to go back</div>
    </main>
  );
}
