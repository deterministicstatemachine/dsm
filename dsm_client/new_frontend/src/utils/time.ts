/** Format a unix timestamp (seconds) as a relative time string. */
export function formatTimeAgo(unixSec: number): string {
  if (!unixSec || unixSec <= 0) return '';
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSec;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 172800) return 'Yesterday';
  const d = new Date(unixSec * 1000);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/** Format a unix timestamp (seconds) as a full date/time string. */
export function formatDateTime(unixSec: number): string {
  if (!unixSec || unixSec <= 0) return 'Unknown';
  const d = new Date(unixSec * 1000);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}
