#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent reference implementation of DSM key schedule KS1.

Written from the specification (`core::identity::key_schedule`), not from the
Rust code: HMAC-BLAKE3 per RFC 2104 (64-byte block, 32-byte output), HKDF
Extract/Expand per RFC 5869, and keyed BLAKE3. It prints the test vectors that
`key_schedule::tests::ks1_test_vectors` asserts, so the two implementations
check each other. Requires the `blake3` Python package.
"""
import struct

import blake3


def H(*parts):
    h = blake3.blake3()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac(key, msg):
    if len(key) > 64:
        key = H(key)
    key = key.ljust(64, b"\0")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return H(opad, H(ipad, msg))


def extract(salt_tag, ikm):
    return hmac(salt_tag + b"\0", ikm)


def expand32(prk, label, *fields):
    info = label + b"\0" + b"".join(fields)
    return hmac(prk, info + b"\x01")  # T(1) = HMAC(PRK, info || 0x01)


def u32(x):
    return struct.pack("<I", x)


def lp(x):
    return u32(len(x)) + x


SEED = b"\x5a" * 64
NET = b"dsm-beta"
G = b"\x47" * 32
DEVID = b"\x44" * 32
APH = b"\x11" * 32

w = extract(b"DSM/kdf/wallet-root/v1", SEED)
ds = expand32(w, b"DSM/device-seed/v3", G, u32(0))
s0 = expand32(w, b"DSM/s0/v3", G, u32(0), APH)
prk_s0 = extract(b"DSM/kdf/s0-root/v1", s0)
sm = expand32(prk_s0, b"DSM/Smaster/v3", G, DEVID, APH)
VECTORS = [
    ("genesis_nonce", expand32(w, b"DSM/genesis-public-nonce/v3", lp(NET), u32(0))),
    ("grk_seed", expand32(w, b"DSM/genesis-root-authority/v2", lp(NET), u32(0), u32(3))),
    ("atta", expand32(w, b"DSM/atta/v3", G, u32(0))),
    ("device_seed", ds),
    ("s0", s0),
    ("sdk_entropy", expand32(w, b"DSM/sdk-entropy/v3", DEVID, G)),
    ("recovery_aead_key", expand32(w, b"DSM/recovery-aead/v2")),
    ("recovery_authority_seed", expand32(w, b"DSM/recovery-authority/v2")),
    ("ak_seed", expand32(extract(b"DSM/kdf/device-root/v1", ds), b"DSM/device-ak/v3", APH)),
    ("smaster", sm),
    ("at_rest_key", expand32(prk_s0, b"DSM/chain-head-at-rest/v3", G, DEVID)),
    ("ml_kem_seed", blake3.blake3(b"DSM/ml-kem-identity/v1\0" + b"ML-KEM-768", key=sm).digest()),
]

if __name__ == "__main__":
    for name, value in VECTORS:
        print(f'("{name}", "{value.hex()}"),')
