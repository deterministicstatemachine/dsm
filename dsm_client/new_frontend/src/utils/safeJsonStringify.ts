/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/utils/safeJsonStringify.ts
// Explicit BigInt-aware JSON stringify helper to avoid global prototype patches.

export function safeJsonStringify(value: unknown): string {
  return JSON.stringify(value, (_key, val) => {
    if (typeof val === 'bigint') return val.toString();
    return val as any;
  });
}
