/* eslint-disable @typescript-eslint/no-explicit-any */
// Object Browser: dev-only UI for storage node object inspection

import React, { useState, useEffect } from "react";
import { fetchObjectForBrowser } from "../../services/storage/objectBrowserService";
import type { ObjectPreview } from "../../services/storage/objectPreviewService";
import { isFeatureEnabled } from "../../config/featureFlags";

export const ObjectBrowserPanel: React.FC = () => {
  const [searchKey, setSearchKey] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [objectBlob, setObjectBlob] = useState<Blob | null>(null);
  const [objectPreview, setObjectPreview] = useState<ObjectPreview | null>(null);
  const [contentType, setContentType] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [featureEnabled, setFeatureEnabled] = useState(false);

  useEffect(() => {
    isFeatureEnabled("storageObjectBrowser").then(setFeatureEnabled);
  }, []);

  if (!featureEnabled) {
    return (
      <div className="snd-card storage-card-body">
        <div className="snd-stat-label storage-card-title">OBJECT BROWSER</div>
        <div className="storage-card-copy storage-card-copy-muted">
          Object browser is disabled in production builds.
        </div>
      </div>
    );
  }

  async function fetchObject(key: string) {
    if (!key) return;
    setLoading(true);
    setError(null);
    setSelectedKey(key);
    try {
      const result = await fetchObjectForBrowser(key);
      if (!result) {
        setError("Object not found");
        setObjectBlob(null);
        setObjectPreview(null);
        setContentType(undefined);
      } else {
        setObjectBlob(result.blob);
        setObjectPreview(result.preview);
        setContentType(result.contentType);
      }
    } catch (e: any) {
      setError(e?.message ?? "Failed to fetch object");
      setObjectBlob(null);
      setObjectPreview(null);
      setContentType(undefined);
    } finally {
      setLoading(false);
    }
  }

  function downloadObject() {
    if (!objectBlob || !selectedKey) return;
    const blob = objectBlob;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = selectedKey.replace(/\//g, "_");
    a.click();
    URL.revokeObjectURL(url);
  }

  function renderPreview() {
    if (!objectPreview) return null;

    if (objectPreview.kind === "binary") {
      return (
        <div className="storage-card-copy">
          Binary data ({objectPreview.size} bytes)
          <div className="storage-browser-meta">Hex preview: {objectPreview.hexPreview}</div>
        </div>
      );
    }

    return <pre className="storage-browser-preview">{objectPreview.textPreview}</pre>;
  }

  return (
    <div className="snd-stack">
      <div className="storage-section-title">Object Browser</div>

      <div className="snd-card storage-card-body">
        <div className="storage-card-copy storage-card-copy-muted">
          Read-only object inspection. Use this to verify storage node contents.
        </div>
      </div>

      {error && (
        <div className="snd-card storage-card-body">
          <div className="snd-stat-label storage-card-title">ERROR</div>
          <div className="storage-card-copy">{error}</div>
        </div>
      )}

      {/* Search/Get */}
      <div className="snd-card storage-card-body">
        <div className="snd-stat-label storage-card-title">GET OBJECT</div>
        <input
          type="text"
          placeholder="Object key (e.g., genesis/abc123...)"
          value={searchKey}
          onChange={(e) => setSearchKey(e.target.value)}
          className="snd-input"
        />
        <div className="storage-top-gap-sm">
          <button
            className="snd-btn"
            onClick={() => fetchObject(searchKey)}
            disabled={loading || !searchKey}
          >
            {loading ? "Loading\u2026" : "Fetch"}
          </button>
        </div>
      </div>

      {/* Preview */}
      {selectedKey && (
        <div className="snd-card storage-card-body">
          <div className="storage-browser-header">
            <div className="storage-text-strong">{selectedKey}</div>
            {objectBlob && (
              <button className="snd-btn-sm" onClick={downloadObject}>
                Download
              </button>
            )}
          </div>
          {contentType && <div className="storage-browser-meta">Content-Type: {contentType}</div>}
          {renderPreview()}
        </div>
      )}
    </div>
  );
};
