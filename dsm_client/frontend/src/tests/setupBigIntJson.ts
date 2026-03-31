// Do not mutate BigInt.prototype in tests.
// If JSON serialization of BigInt is needed, import and use the helper below.
export function safeJsonStringify(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => (typeof value === 'bigint' ? value.toString() : value));
}
