#!/usr/bin/env python3
"""Decode a pulled dsm_client.db's bcr_device_heads.head_bytes (DeviceState codec v0x06) on the host.

usage: dsm_head_decode.py <dsm_client.db> [vault_id_b32]
Prints: genesis/devid, balances (policy_commit_b32 -> amount), and vault reserve leaves
(key -> amount, sequence). With a vault id, also derives each leg's leaf key from
amm_vault_records (BLAKE3 domain tag "DSM/vault-reserve/v1" via b3sum) and names the legs.
Read-only. No hex in output (Base32 Crockford, per repo policy).
"""
import sqlite3, struct, subprocess, sys

ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
def b32(b: bytes) -> str:
    bits = 0; acc = 0; out = []
    for x in b:
        acc = (acc << 8) | x; bits += 8
        while bits >= 5:
            out.append(ALPHA[(acc >> (bits - 5)) & 31]); bits -= 5
    if bits: out.append(ALPHA[(acc << (5 - bits)) & 31])
    return "".join(out)

def b3(tag: bytes, *parts: bytes) -> bytes:
    data = tag + b"\x00" + b"".join(parts)
    out = subprocess.run(["b3sum", "--no-names", "--raw"], input=data, capture_output=True, check=True).stdout
    return out

def decode(head: bytes):
    p = 0
    def take(n):
        nonlocal p; v = head[p:p+n]; p += n; return v
    def u32(): return struct.unpack("<I", take(4))[0]
    def u64(): return struct.unpack("<Q", take(8))[0]
    ver = take(1)[0]; assert ver == 0x06, f"codec {ver:#x} != 0x06"
    genesis = take(32); devid = take(32)
    pk = take(u32()); root = take(32)
    flag = take(1)[0]
    if flag: take(32)
    balances = {}
    for _ in range(u32()):
        pc = take(32); balances[b32(pc)] = u64()
    tips = u32()
    for _ in range(tips):
        take(32); take(32); take(32); take(1); take(u32())
    for _ in range(u32()): take(32); take(32)
    for _ in range(u32()): take(32); u64(); u64()
    reserves = {}
    for _ in range(u32()):
        k = take(32); a = u64(); s = u64(); reserves[k] = (a, s)
    return dict(genesis=genesis, devid=devid, root=root, balances=balances, tips=tips, reserves=reserves)

def main():
    db = sys.argv[1]; vault_b32 = sys.argv[2] if len(sys.argv) > 2 else None
    c = sqlite3.connect(db)
    row = c.execute("SELECT device_id, head_bytes FROM bcr_device_heads").fetchone()
    if not row: print("no device head"); return 2
    h = decode(row[1])
    print(f"devid={b32(h['devid'])[:16]}… genesis={b32(h['genesis'])[:16]}… root={b32(h['root'])[:16]}… tips={h['tips']}")
    for pc, amt in h["balances"].items(): print(f"balance {pc[:12]}… = {amt}")
    print(f"reserve leaves: {len(h['reserves'])}")
    recs = c.execute("SELECT vault_id, owner_genesis, owner_devid, policy_commit_a, policy_commit_b, fee_bps FROM amm_vault_records").fetchall()
    for vid, og, od, pa, pb, fee in recs:
        if vault_b32 and not b32(vid).startswith(vault_b32.rstrip("…")): continue
        print(f"vault {b32(vid)[:16]}… fee={fee}")
        for label, pc in (("A", pa), ("B", pb)):
            key = b3(b"DSM/vault-reserve/v1", og, od, vid, pc)
            v = h["reserves"].get(key)
            print(f"  leg {label} {b32(pc)[:12]}… -> {'amount=%d seq=%d' % v if v else 'NO LEAF'}")
    return 0

if __name__ == "__main__": sys.exit(main())
