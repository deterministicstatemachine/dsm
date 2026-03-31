export type KvMap = Map<string, string>;

export function parseKv(text: string): KvMap {
  const m: KvMap = new Map();
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.trim();
    if (line.length === 0) continue;
    if (line.startsWith("#")) continue;

    const eq = line.indexOf("=");
    if (eq <= 0) {
      throw new Error(`invalid kv line ${i + 1}: ${raw}`);
    }

    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();

    if (key.length === 0) throw new Error(`empty key on line ${i + 1}`);
    m.set(key, val);
  }

  return m;
}
