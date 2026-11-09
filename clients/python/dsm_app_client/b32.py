# SPDX-License-Identifier: MIT OR Apache-2.0
"""Base32 Crockford, as DSM writes every identifier for people to read
(`dsm::utils::text_id`): 0-9 and A-Z without I, L, O and U, no padding."""

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def encode_b32(data: bytes) -> str:
    out = []
    buffer = 0
    bits = 0
    for b in data:
        buffer = ((buffer << 8) | b) & 0xFFFF
        bits += 8
        while bits >= 5:
            out.append(ALPHABET[(buffer >> (bits - 5)) & 31])
            bits -= 5
    if bits > 0:
        out.append(ALPHABET[(buffer << (5 - bits)) & 31])
    return "".join(out)


def _value(ch: str) -> int:
    c = ch.upper()
    if c == "O":
        return 0
    if c in ("I", "L"):
        return 1
    v = ALPHABET.find(c)
    if v < 0:
        raise ValueError(f"{ch!r} is not a Base32 Crockford character")
    return v


def decode_b32(text: str) -> bytes:
    out = bytearray()
    buffer = 0
    bits = 0
    for ch in text:
        if ch in "- ":
            continue
        buffer = ((buffer << 5) | _value(ch)) & 0xFFFF
        bits += 5
        while bits >= 8:
            out.append((buffer >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


def decode_id(text: str, what: str) -> bytes:
    """A 32-byte identifier from its Base32 Crockford text; refuses any other length."""
    data = decode_b32(text)
    if len(data) != 32:
        raise ValueError(f"{what} is {len(data)} bytes, not 32: {text}")
    return data
