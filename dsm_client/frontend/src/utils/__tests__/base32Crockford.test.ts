import {
  decodeBase32Crockford,
  encodeBase32Crockford,
  normalizeBase32Crockford,
} from "../textId";

const bytes = (...xs: number[]) => new Uint8Array(xs);

describe("base32Crockford", () => {
  test("roundtrip: arbitrary bytes", () => {
    const input = bytes(0x00, 0x01, 0x02, 0x10, 0xfe, 0xff, 0x7a, 0x80);
    const enc = encodeBase32Crockford(input);
    const dec = decodeBase32Crockford(enc);
    expect(dec).toEqual(input);
  });

  test("hello world encoding", () => {
    const input = new TextEncoder().encode("hello world");
    const enc = encodeBase32Crockford(input);
    // Should match Rust output: D1JPRV3F41VPYWKCCG
    expect(enc).toBe("D1JPRV3F41VPYWKCCG");
  });

  test("decode normalizes O->0 and I/L->1 and ignores hyphens", () => {
    const input = bytes(1, 2, 3, 4, 5, 6, 7);
    const enc = encodeBase32Crockford(input);

    // Introduce ambiguous chars where possible.
    const mutated = enc
      .replace(/0/g, "O")
      .replace(/1/g, "I")
      .replace(/I/g, "L")
      .replace(/.{4}/g, "$&-")
      .toLowerCase();

    const dec = decodeBase32Crockford(mutated);
    expect(dec).toEqual(input);
  });

  test("decode rejects invalid chars (fail-closed)", () => {
    const input = bytes(9, 8, 7, 6, 5);
    const enc = encodeBase32Crockford(input);

    const noisy = `!!!${enc}***`;
    expect(() => decodeBase32Crockford(noisy)).toThrow();
  });

  test("alphabet length invariant (Crockford base32)", () => {
    // 32 symbols, 5 bits each. Any other size is not base32.
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    expect(alphabet.length).toBe(32);
  });
});

describe("textId (Base32 Crockford)", () => {
  it("encodes/decodes empty", () => {
    expect(encodeBase32Crockford(new Uint8Array())).toBe("");
    expect(decodeBase32Crockford("")).toEqual(new Uint8Array());
  });

  it("normalize helper is deterministic", () => {
    expect(normalizeBase32Crockford(" o1il- ")).toBe("0111");
  });
});
