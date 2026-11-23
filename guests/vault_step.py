# One SoFi vault step, DSM Core's checks (docs/plans/2026-11-22-vault-step-proof-statement.md, 1..9), as a leanVM
# program over the BLAKE3 instruction. Research build; the Rust reference it must agree with is
# crates/vault_step/src/reference.rs, a port of Core main cc9e44b36 matched against Core's own digests.
#
# Representations:
# - a 32-byte value is two cells, its bytes little-endian in the limbs (BLAKE3's word order);
# - a byte string to hash is a run of NIBBLE PATTERNS, two a byte, low nibble first, each a K element of degree < 4;
# - an integer is a run of digits in the exponent, g^d with d < 16, least significant first. Adding is multiplying,
#   a digit's range check is 3 cycles, and a digit product is one lookup in the table MT, MT[g^(a + 16 b)] = g^(a b).
# Every hinted digit is range-checked, and every value taken apart is rebuilt and compared, so a byte placed in a
# message is exactly the byte of the value it came from.
from snark_lib import *

Y_TOWER = 18446744073709551616
B3_IV0 = B3_IV0_PLACEHOLDER
B3_IV1 = B3_IV1_PLACEHOLDER
# The tags, as byte lists (each hash's prefix is its tag, then a NUL).
TAG_STATE_KEY = TAG_STATE_KEY_PLACEHOLDER
TAG_LEAF_STATE = TAG_LEAF_STATE_PLACEHOLDER
TAG_REL_KEY = TAG_REL_KEY_PLACEHOLDER
TAG_REL_LEAF = TAG_REL_LEAF_PLACEHOLDER
TAG_SUCC_CELL = TAG_SUCC_CELL_PLACEHOLDER
TAG_MARKET_OBJ = TAG_MARKET_OBJ_PLACEHOLDER
TAG_FEE_OBJ = TAG_FEE_OBJ_PLACEHOLDER
TAG_STORAGE_OBJ = TAG_STORAGE_OBJ_PLACEHOLDER
TAG_STATEMENT = TAG_STATEMENT_PLACEHOLDER
# The first compression's message cells of a tree node, a tree leaf and an attempt key: the 24-byte tag and its NUL,
# then zeros, X and Y filling bytes 25..64 (the BLAKE3 instruction's placed inputs).
NODE_M = NODE_M_PLACEHOLDER
LEAF_M = LEAF_M_PLACEHOLDER
ATTEMPT_M = ATTEMPT_M_PLACEHOLDER
# Metadata cells: chunk counter 0 in the low limb, block_len | flags << 32 in the high one.
MD_64_START = MD_64_START_PLACEHOLDER
MD_25_END = MD_25_END_PLACEHOLDER
MD_1_END = MD_1_END_PLACEHOLDER
TWO_32 = 4294967296
# Core's constants.
ENV_STATE_LEAF = [0, 75, 0, 1]
ENV_REL_LEAF = [0, 76, 0, 1]
ENV_MARKET = [0, 7, 0, 1]
FAMILY_VERSION = [0, 1, 0, 1]
ENV_FEE = [0, 10, 0, 1]
STATUS_ACTIVE = [0, 1]
BPS = [0, 1, 7, 2]  # 10,000 = 0x2710, as digits


# ======================================================================== tables

def nib_table():
    # NIB[g^d] = d as a bit pattern.
    t = HeapBuf(16)
    for d in unroll(0, 16):
        t[GEN ** d] = d
    return t


def mul_table():
    # MT[g^(a + 16 b)] = g^(a b).
    t = HeapBuf(256)
    for a in unroll(0, 16):
        for b in unroll(0, 16):
            t[GEN ** (a + 16 * b)] = GEN ** (a * b)
    return t


def bit_table():
    # BT[g^(16 t + d)] = bit t of d.
    t = HeapBuf(64)
    for b in unroll(0, 4):
        for d in unroll(0, 16):
            t[GEN ** (16 * b + d)] = const((d // 2 ** b) % 2)
    return t


# =================================================================== values

def value_nibbles(c0, c1, nib):
    # The 64 nibble patterns of the 32-byte value (c0, c1), and its 64 digits, proven: hinted digits, each below 16,
    # whose patterns rebuild both cells.
    d = HeapBuf(64)
    p = HeapBuf(64)
    hint_windows_exponent(d, c0, 0, 4, 32)
    hint_windows_exponent(d, c1, 0, 4, 32, 32)
    for k in unroll(0, 64):
        dk = d[GEN ** k]
        assert log(dk) < 16
        p[GEN ** k] = nib[dk]
    for c in unroll(0, 2):
        lo = 0
        hi = 0
        for k in unroll(0, 16):
            lo = lo + p[GEN ** (32 * c + k)] * GEN ** (4 * k)
            hi = hi + p[GEN ** (32 * c + 16 + k)] * GEN ** (4 * k)
        if const(c == 0):
            assert lo + Y_TOWER * hi == c0
        else:
            assert lo + Y_TOWER * hi == c1
    return p, d


def hinted_value(nib):
    # The next 32-byte value of the stream `value`: its two cells, then its nibbles.
    c = StackBuf(2)
    hint_witness(c, "value")
    p, d = value_nibbles(c[0], c[1], nib)
    return c[0], c[1], p, d


def digits(n: Const):
    # The next integer of the stream `digits`, n digits, each range-checked.
    d = HeapBuf(GEN ** n)
    hint_witness(d[0:n], "digits")
    for k in unroll(0, n):
        assert log(d[GEN ** k]) < 16
    return d


def int_limb(d, nib, n: Const):
    # The integer's low 64 bits as a K element: its first 16 digits' patterns.
    v = 0
    for k in unroll(0, n):
        v = v + nib[d[GEN ** k]] * GEN ** (4 * k)
    return v


# ============================================================== integers

def add_digits(a, na: Const, b, nb: Const, out, n: Const, cin):
    # out = a + b + cin (cin g^0 or g^1), n digits; a carry out of the top digit is refused. Digits past a run are 0.
    carry = cin
    for k in unroll(0, n):
        s = carry
        if const(k // na == 0):
            s = s * a[GEN ** k]
        if const(k // nb == 0):
            s = s * b[GEN ** k]
        split = StackBuf(2)
        hint_decompose_digits_exponent(split, s, 5, 2, 4, 0)
        r = split[0]
        c = split[1]
        assert log(r) < 16
        assert log(c) < 2
        c2 = c * c
        c4 = c2 * c2
        c8 = c4 * c4
        assert s == r * c8 * c8
        out[GEN ** k] = r
        carry = c
    assert carry == 1
    return


def mul_digits(a, na: Const, b, nb: Const, out, mt):
    # out = a * b, na + nb digits.
    b16 = StackBuf(32)  # nb <= 32
    for j in unroll(0, nb):
        x = b[GEN ** j]
        x2 = x * x
        x4 = x2 * x2
        x8 = x4 * x4
        b16[j] = x8 * x8
    carry = 1
    for k in unroll(0, na + nb):
        s = carry
        for i in unroll(0, na):
            if const(i // (k + 1) == 0):
                if const((k - i) // nb == 0):
                    s = s * mt[a[GEN ** i] * b16[k - i]]
        split = StackBuf(3)
        hint_decompose_digits_exponent(split, s, 12, 3, 4, 0)
        assert log(split[0]) < 16
        assert log(split[1]) < 16
        assert log(split[2]) < 16
        h2 = split[2] * split[2]
        h4 = h2 * h2
        h8 = h4 * h4
        c = split[1] * h8 * h8
        c2 = c * c
        c4 = c2 * c2
        c8 = c4 * c4
        assert s == split[0] * c8 * c8
        out[GEN ** k] = split[0]
        carry = c
    assert carry == 1
    return


def assert_digits_equal(a, b, n: Const):
    for k in unroll(0, n):
        assert a[GEN ** k] == b[GEN ** k]
    return


def mux_digits(bit, x, y, out, n: Const):
    # out = bit ? x : y.
    for k in unroll(0, n):
        yk = y[GEN ** k]
        out[GEN ** k] = yk + bit * (x[GEN ** k] + yk)
    return


# ================================================================ hashing

def hash_msg(m, n: Const):
    # BLAKE3 of the n bytes whose nibble patterns m holds, n <= 1024: one chunk, chained compressions.
    cv = StackBuf(2)
    cv[0] = B3_IV0
    cv[1] = B3_IV1
    for blk in unroll(0, (n + 63) // 64):
        mc = StackBuf(4)
        for c in unroll(0, 4):
            lo = 0
            hi = 0
            for k in unroll(0, 16):
                if const((2 * (64 * blk + 16 * c) + k) // (2 * n) == 0):
                    lo = lo + m[GEN ** (2 * (64 * blk + 16 * c) + k)] * GEN ** (4 * k)
                if const((2 * (64 * blk + 16 * c) + k + 16) // (2 * n) == 0):
                    hi = hi + m[GEN ** (2 * (64 * blk + 16 * c) + k + 16)] * GEN ** (4 * k)
            mc[c] = lo + Y_TOWER * hi
        nxt = StackBuf(2)
        if const(blk == 0):
            if const((n - 1) // 64 == 0):
                blake3(mc[0:2], mc[2:4], cv, const((n + 11 * TWO_32) * Y_TOWER), nxt)
            else:
                blake3(mc[0:2], mc[2:4], cv, const((64 + TWO_32) * Y_TOWER), nxt)
        else:
            if const(blk == (n + 63) // 64 - 1):
                blake3(mc[0:2], mc[2:4], cv, const((n - 64 * blk + 10 * TWO_32) * Y_TOWER), nxt)
            else:
                blake3(mc[0:2], mc[2:4], cv, const(64 * Y_TOWER), nxt)
        cv = nxt
    return cv


def put_value(m, at: Const, p):
    # The 32 bytes of a value at byte `at`.
    for k in unroll(0, 64):
        m[GEN ** (2 * at + k)] = p[GEN ** k]
    return


def put_u64_be(m, at: Const, d, nib):
    # A 16-digit integer as 8 big-endian bytes at byte `at`.
    for j in unroll(0, 8):
        m[GEN ** (2 * (at + j))] = nib[d[GEN ** (14 - 2 * j)]]
        m[GEN ** (2 * (at + j) + 1)] = nib[d[GEN ** (15 - 2 * j)]]
    return


def tree_node(bit, c0, c1, s0, s1, mcells):
    # H(tag || 0 || L || R): the current digest on the left when `bit` is 0, else the sibling. The BLAKE3 instruction
    # places L at bytes 25..57, R's first 7 bytes at 57..64 and its last 25 at 0..25 of the second block.
    x = StackBuf(2)
    y = StackBuf(2)
    x[0] = c0 + bit * (c0 + s0)
    x[1] = c1 + bit * (c1 + s1)
    y[0] = s0 + bit * (s0 + c0)
    y[1] = s1 + bit * (s1 + c1)
    m = StackBuf(4)
    for c in unroll(0, 4):
        m[c] = mcells[GEN ** c]
    cv = StackBuf(2)
    cv[0] = B3_IV0
    cv[1] = B3_IV1
    z = StackBuf(2)
    z[0] = 0
    z[1] = 0
    t = StackBuf(2)
    blake3(m[0:2], m[2:4], cv, MD_64_START, t, x=x, y=y)
    o = StackBuf(2)
    blake3(z, z, t, MD_25_END, o, w=y)
    return o


# ================================================================== main

def main():
    nib = nib_table()
    mt = mul_table()
    bt = bit_table()
    node_m = HeapBuf(4)
    leaf_m = HeapBuf(4)
    attempt_m = HeapBuf(4)
    for c in unroll(0, 4):
        node_m[GEN ** c] = NODE_M[c]
        leaf_m[GEN ** c] = LEAF_M[c]
        attempt_m[GEN ** c] = ATTEMPT_M[c]

    # ---- the values: public, then private ----
    v0, v1, vp, vd = hinted_value(nib)
    rp0, rp1, rpp, rpd = hinted_value(nib)
    e0, e1, ep, ed = hinted_value(nib)
    g0, g1, gp, gd_ = hinted_value(nib)
    dv0, dv1, dvp, dvd = hinted_value(nib)
    h0, h1, hp, hd = hinted_value(nib)
    og0, og1, ogp, ogd = hinted_value(nib)
    od0, od1, odp, odd = hinted_value(nib)
    rl0, rl1, rlp, rld = hinted_value(nib)
    ss0, ss1, ssp, ssd = hinted_value(nib)
    ta0, ta1, tap, tad = hinted_value(nib)
    tb0, tb1, tbp, tbd = hinted_value(nib)
    position = digits(16)
    generation = digits(16)
    reserve_a = digits(16)
    reserve_b = digits(16)
    amount_in = digits(16)
    amount_out = digits(16)
    attempt = digits(16)
    fee = digits(8)
    flags = StackBuf(2)
    hint_witness(flags, "flags")  # in_is_a, relationship present
    in_is_a = flags[0]
    present = flags[1]
    assert in_is_a * in_is_a == in_is_a
    assert present * present == present

    # ---- 2: the pair is the market policy's, which decodes only strictly ordered (token_a < token_b) ----
    # Byte-wise big-endian: token_b = token_a + t + 1 for some t, over the digits in big-endian order.
    ta_be = HeapBuf(64)
    tb_be = HeapBuf(64)
    for j in unroll(0, 32):
        # Digit 2j + 1 of the value (its byte j's high nibble) is the more significant.
        ta_be[GEN ** (63 - 2 * j)] = tad[GEN ** (2 * j + 1)]
        ta_be[GEN ** (62 - 2 * j)] = tad[GEN ** (2 * j)]
        tb_be[GEN ** (63 - 2 * j)] = tbd[GEN ** (2 * j + 1)]
        tb_be[GEN ** (62 - 2 * j)] = tbd[GEN ** (2 * j)]
    gap = digits(64)
    tb_check = HeapBuf(64)
    add_digits(ta_be, 64, gap, 64, tb_check, 64, GEN)
    assert_digits_equal(tb_check, tb_be, 64)

    # ---- the policies the state commits: their addresses ----
    mm = HeapBuf(200)
    for i in unroll(0, len(TAG_MARKET_OBJ)):
        mm[GEN ** (2 * i)] = const(TAG_MARKET_OBJ[i] % 16)
        mm[GEN ** (2 * i + 1)] = const(TAG_MARKET_OBJ[i] // 16)
    mm[GEN ** 54] = 0
    mm[GEN ** 55] = 0
    for i in unroll(0, 4):
        mm[GEN ** (56 + 2 * i)] = const(ENV_MARKET[i] % 16)
        mm[GEN ** (57 + 2 * i)] = const(ENV_MARKET[i] // 16)
        mm[GEN ** (64 + 2 * i)] = const(FAMILY_VERSION[i] % 16)
        mm[GEN ** (65 + 2 * i)] = const(FAMILY_VERSION[i] // 16)
    put_value(mm, 36, tap)
    put_value(mm, 68, tbp)
    m_inner = hash_msg(mm, 100)
    mip, mid = value_nibbles(m_inner[0], m_inner[1], nib)
    ma = HeapBuf(156)
    for i in unroll(0, len(TAG_STORAGE_OBJ)):
        ma[GEN ** (2 * i)] = const(TAG_STORAGE_OBJ[i] % 16)
        ma[GEN ** (2 * i + 1)] = const(TAG_STORAGE_OBJ[i] // 16)
    ma[GEN ** 36] = 0
    ma[GEN ** 37] = 0
    for i in unroll(0, len(TAG_MARKET_OBJ)):
        ma[GEN ** (38 + 2 * i)] = const(TAG_MARKET_OBJ[i] % 16)
        ma[GEN ** (39 + 2 * i)] = const(TAG_MARKET_OBJ[i] // 16)
    put_value(ma, 46, mip)
    market = hash_msg(ma, 78)
    mpp, mpd = value_nibbles(market[0], market[1], nib)

    fm = HeapBuf(66)
    for i in unroll(0, len(TAG_FEE_OBJ)):
        fm[GEN ** (2 * i)] = const(TAG_FEE_OBJ[i] % 16)
        fm[GEN ** (2 * i + 1)] = const(TAG_FEE_OBJ[i] // 16)
    fm[GEN ** 48] = 0
    fm[GEN ** 49] = 0
    for i in unroll(0, 4):
        fm[GEN ** (50 + 2 * i)] = const(ENV_FEE[i] % 16)
        fm[GEN ** (51 + 2 * i)] = const(ENV_FEE[i] // 16)
    for j in unroll(0, 4):
        fm[GEN ** (58 + 2 * j)] = nib[fee[GEN ** (6 - 2 * j)]]
        fm[GEN ** (59 + 2 * j)] = nib[fee[GEN ** (7 - 2 * j)]]
    f_inner = hash_msg(fm, 33)
    fip, fid = value_nibbles(f_inner[0], f_inner[1], nib)
    fa = HeapBuf(150)
    for i in unroll(0, len(TAG_STORAGE_OBJ)):
        fa[GEN ** (2 * i)] = const(TAG_STORAGE_OBJ[i] % 16)
        fa[GEN ** (2 * i + 1)] = const(TAG_STORAGE_OBJ[i] // 16)
    fa[GEN ** 36] = 0
    fa[GEN ** 37] = 0
    for i in unroll(0, len(TAG_FEE_OBJ)):
        fa[GEN ** (38 + 2 * i)] = const(TAG_FEE_OBJ[i] % 16)
        fa[GEN ** (39 + 2 * i)] = const(TAG_FEE_OBJ[i] // 16)
    put_value(fa, 43, fip)
    fee_policy = hash_msg(fa, 75)
    fpp, fpd = value_nibbles(fee_policy[0], fee_policy[1], nib)

    # ---- 3: the price rule, amount_out = floor(r_out a' / (r_in 10^4 + a')), a' = amount_in (10^4 - fee) ----
    r_in = HeapBuf(16)
    r_out = HeapBuf(16)
    mux_digits(in_is_a, reserve_a, reserve_b, r_in, 16)
    mux_digits(in_is_a, reserve_b, reserve_a, r_out, 16)
    bps = HeapBuf(4)
    for k in unroll(0, 4):
        bps[GEN ** k] = GEN ** BPS[k]
    fee_c = digits(4)  # 10^4 - fee: fee + fee_c = 10^4, fee_c nonzero, so fee < 10^4
    fee_sum = HeapBuf(8)
    add_digits(fee, 8, fee_c, 4, fee_sum, 8, 1)
    assert_digits_equal(fee_sum, bps, 4)
    for k in unroll(4, 8):
        assert fee_sum[GEN ** k] == 1
    fee_c_limb = int_limb(fee_c, nib, 4)
    assert fee_c_limb != 0
    after_fee = HeapBuf(20)
    mul_digits(amount_in, 16, fee_c, 4, after_fee, mt)
    r_in_bps = HeapBuf(20)
    mul_digits(r_in, 16, bps, 4, r_in_bps, mt)
    den = HeapBuf(21)
    add_digits(r_in_bps, 20, after_fee, 20, den, 21, 1)
    num = HeapBuf(36)
    mul_digits(r_out, 16, after_fee, 20, num, mt)
    for k in unroll(32, 36):
        assert num[GEN ** k] == 1  # num below 2^128, as Core's checked u128 product requires
    # num = amount_out den + rem, rem < den.
    rem = digits(21)
    prod = HeapBuf(37)
    mul_digits(amount_out, 16, den, 21, prod, mt)
    total = HeapBuf(37)
    add_digits(prod, 37, rem, 21, total, 37, 1)
    assert_digits_equal(total, num, 36)
    assert total[GEN ** 36] == 1
    slack = digits(21)
    den_check = HeapBuf(21)
    add_digits(rem, 21, slack, 21, den_check, 21, GEN)
    assert_digits_equal(den_check, den, 21)
    amount_in_limb = int_limb(amount_in, nib, 16)
    assert amount_in_limb != 0
    amount_out_limb = int_limb(amount_out, nib, 16)
    assert amount_out_limb != 0
    r_in_limb = int_limb(r_in, nib, 16)
    assert r_in_limb != 0
    r_out_limb = int_limb(r_out, nib, 16)
    assert r_out_limb != 0

    # ---- 4, 5: the reserves and the generation ----
    new_in = HeapBuf(16)
    add_digits(r_in, 16, amount_in, 16, new_in, 16, 1)
    new_out = digits(16)
    out_check = HeapBuf(16)
    add_digits(new_out, 16, amount_out, 16, out_check, 16, 1)
    assert_digits_equal(out_check, r_out, 16)
    new_out_limb = int_limb(new_out, nib, 16)
    assert new_out_limb != 0
    reserve_a2 = HeapBuf(16)
    reserve_b2 = HeapBuf(16)
    mux_digits(in_is_a, new_in, new_out, reserve_a2, 16)
    mux_digits(in_is_a, new_out, new_in, reserve_b2, 16)
    generation2 = HeapBuf(16)
    zero1 = HeapBuf(1)
    zero1[1] = 1
    add_digits(generation, 16, zero1, 1, generation2, 16, GEN)

    # ---- 6: the state leaf's value, before and after: the same bytes but for the generation and the reserves ----
    sm = HeapBuf(518)
    for i in unroll(0, len(TAG_LEAF_STATE)):
        sm[GEN ** (2 * i)] = const(TAG_LEAF_STATE[i] % 16)
        sm[GEN ** (2 * i + 1)] = const(TAG_LEAF_STATE[i] // 16)
    sm[GEN ** 56] = 0
    sm[GEN ** 57] = 0
    for i in unroll(0, 4):
        sm[GEN ** (58 + 2 * i)] = const(ENV_STATE_LEAF[i] % 16)
        sm[GEN ** (59 + 2 * i)] = const(ENV_STATE_LEAF[i] // 16)
    put_value(sm, 33, ogp)
    put_value(sm, 65, odp)
    put_u64_be(sm, 97, position, nib)
    put_value(sm, 105, mpp)
    put_value(sm, 137, fpp)
    put_value(sm, 169, rlp)
    put_value(sm, 201, ssp)
    sm2 = HeapBuf(518)
    for k in unroll(0, 466):
        sm2[GEN ** k] = sm[GEN ** k]
    put_u64_be(sm, 233, generation, nib)
    put_u64_be(sm, 241, reserve_a, nib)
    put_u64_be(sm, 249, reserve_b, nib)
    put_u64_be(sm2, 233, generation2, nib)
    put_u64_be(sm2, 241, reserve_a2, nib)
    put_u64_be(sm2, 249, reserve_b2, nib)
    for i in unroll(0, 2):
        sm[GEN ** (514 + 2 * i)] = const(STATUS_ACTIVE[i] % 16)
        sm[GEN ** (515 + 2 * i)] = const(STATUS_ACTIVE[i] // 16)
        sm2[GEN ** (514 + 2 * i)] = const(STATUS_ACTIVE[i] % 16)
        sm2[GEN ** (515 + 2 * i)] = const(STATUS_ACTIVE[i] // 16)
    state_pre = hash_msg(sm, 259)
    state_post = hash_msg(sm2, 259)
    km = HeapBuf(120)
    for i in unroll(0, len(TAG_STATE_KEY)):
        km[GEN ** (2 * i)] = const(TAG_STATE_KEY[i] % 16)
        km[GEN ** (2 * i + 1)] = const(TAG_STATE_KEY[i] // 16)
    km[GEN ** 54] = 0
    km[GEN ** 55] = 0
    put_value(km, 28, vp)
    state_key = hash_msg(km, 60)

    # ---- 7: the trader's relationship leaf ----
    rk = HeapBuf(232)
    for i in unroll(0, len(TAG_REL_KEY)):
        rk[GEN ** (2 * i)] = const(TAG_REL_KEY[i] % 16)
        rk[GEN ** (2 * i + 1)] = const(TAG_REL_KEY[i] // 16)
    rk[GEN ** 38] = 0
    rk[GEN ** 39] = 0
    put_value(rk, 20, gp)
    put_value(rk, 52, dvp)
    put_value(rk, 84, vp)
    rel_key = hash_msg(rk, 116)
    nm = HeapBuf(170)
    for i in unroll(0, len(TAG_REL_LEAF)):
        nm[GEN ** (2 * i)] = const(TAG_REL_LEAF[i] % 16)
        nm[GEN ** (2 * i + 1)] = const(TAG_REL_LEAF[i] // 16)
    nm[GEN ** 40] = 0
    nm[GEN ** 41] = 0
    put_value(nm, 21, hp)
    put_value(nm, 53, ep)
    rel_next = hash_msg(nm, 85)
    np_, nd_ = value_nibbles(rel_next[0], rel_next[1], nib)
    lm = HeapBuf(258)
    for i in unroll(0, len(TAG_LEAF_STATE)):
        lm[GEN ** (2 * i)] = const(TAG_LEAF_STATE[i] % 16)
        lm[GEN ** (2 * i + 1)] = const(TAG_LEAF_STATE[i] // 16)
    lm[GEN ** 56] = 0
    lm[GEN ** 57] = 0
    for i in unroll(0, 4):
        lm[GEN ** (58 + 2 * i)] = const(ENV_REL_LEAF[i] % 16)
        lm[GEN ** (59 + 2 * i)] = const(ENV_REL_LEAF[i] // 16)
    put_value(lm, 33, gp)
    put_value(lm, 65, dvp)
    lm2 = HeapBuf(258)
    for k in unroll(0, 194):
        lm2[GEN ** k] = lm[GEN ** k]
    put_value(lm, 97, hp)
    put_value(lm2, 97, np_)
    rel_pre = hash_msg(lm, 129)
    rel_post = hash_msg(lm2, 129)

    # ---- 8: the tree. Both leaves against R_prev with one write set; the same siblings give R_next ----
    kp1, kd1 = value_nibbles(state_key[0], state_key[1], nib)
    kp2, kd2 = value_nibbles(rel_key[0], rel_key[1], nib)
    rb1 = HeapBuf(256)
    rb2 = HeapBuf(256)
    for i in unroll(0, 256):
        # Iteration i is level 255 - i; Core's get_bit takes bit 7 - level % 8 of byte level / 8, MSB first: digit
        # 2 (level / 8) + (that bit) / 4 of the value, bit (that bit) % 4 of it.
        rb1[GEN ** i] = bt[GEN ** (16 * ((7 - (255 - i) % 8) % 4)) * kd1[GEN ** (2 * ((255 - i) // 8) + (7 - (255 - i) % 8) // 4)]]
        rb2[GEN ** i] = bt[GEN ** (16 * ((7 - (255 - i) % 8) % 4)) * kd2[GEN ** (2 * ((255 - i) // 8) + (7 - (255 - i) % 8) // 4)]]
    path1 = HeapBuf(512)
    path2 = HeapBuf(512)
    hint_witness(path1[0:512], "state_path")
    hint_witness(path2[0:512], "relationship_path")
    # Rows of the fold: entry 1 (the state leaf) and entry 2 (the relationship leaf), before and after.
    p1 = HeapBuf(514)
    q1 = HeapBuf(514)
    p2 = HeapBuf(514)
    q2 = HeapBuf(514)
    l1 = tree_node(0, state_key[0], state_key[1], state_pre[0], state_pre[1], leaf_m)
    p1[1] = l1[0]
    p1[GEN] = l1[1]
    l2 = tree_node(0, state_key[0], state_key[1], state_post[0], state_post[1], leaf_m)
    q1[1] = l2[0]
    q1[GEN] = l2[1]
    l3 = tree_node(0, rel_key[0], rel_key[1], rel_pre[0], rel_pre[1], leaf_m)
    p2[1] = present * l3[0]
    p2[GEN] = present * l3[1]
    l4 = tree_node(0, rel_key[0], rel_key[1], rel_post[0], rel_post[1], leaf_m)
    q2[1] = l4[0]
    q2[GEN] = l4[1]
    # The keys first differ at depth d: below it each entry folds alone, at it the two subtrees meet, above it
    # one path with shared siblings.
    gdiv = hint_witness("divergence")
    assert log(gdiv) < 256
    n_a = GEN ** 255 / gdiv
    for xi in mul_range(1, n_a):
        x2 = xi * xi
        b1 = rb1[xi]
        b2 = rb2[xi]
        s10 = path1[x2]
        s11 = path1[x2 * GEN]
        s20 = path2[x2]
        s21 = path2[x2 * GEN]
        a1 = tree_node(b1, p1[x2], p1[x2 * GEN], s10, s11, node_m)
        p1[x2 * GEN ** 2] = a1[0]
        p1[x2 * GEN ** 3] = a1[1]
        a2 = tree_node(b1, q1[x2], q1[x2 * GEN], s10, s11, node_m)
        q1[x2 * GEN ** 2] = a2[0]
        q1[x2 * GEN ** 3] = a2[1]
        a3 = tree_node(b2, p2[x2], p2[x2 * GEN], s20, s21, node_m)
        p2[x2 * GEN ** 2] = a3[0]
        p2[x2 * GEN ** 3] = a3[1]
        a4 = tree_node(b2, q2[x2], q2[x2 * GEN], s20, s21, node_m)
        q2[x2 * GEN ** 2] = a4[0]
        q2[x2 * GEN ** 3] = a4[1]
    na2 = n_a * n_a
    bd1 = rb1[n_a]
    assert bd1 + rb2[n_a] == 1  # the keys differ at depth d
    up = HeapBuf(514)
    upq = HeapBuf(514)
    m1 = tree_node(bd1, p1[na2], p1[na2 * GEN], p2[na2], p2[na2 * GEN], node_m)
    up[1] = m1[0]
    up[GEN] = m1[1]
    m2 = tree_node(bd1, q1[na2], q1[na2 * GEN], q2[na2], q2[na2 * GEN], node_m)
    upq[1] = m2[0]
    upq[GEN] = m2[1]
    for j in mul_range(1, gdiv):
        xi = n_a * GEN * j
        x2 = xi * xi
        j2 = j * j
        b1 = rb1[xi]
        assert rb2[xi] == b1  # above d the keys agree
        s0 = path1[x2]
        s1 = path1[x2 * GEN]
        u1 = tree_node(b1, up[j2], up[j2 * GEN], s0, s1, node_m)
        up[j2 * GEN ** 2] = u1[0]
        up[j2 * GEN ** 3] = u1[1]
        u2 = tree_node(b1, upq[j2], upq[j2 * GEN], s0, s1, node_m)
        upq[j2 * GEN ** 2] = u2[0]
        upq[j2 * GEN ** 3] = u2[1]
    gd2 = gdiv * gdiv
    assert up[gd2] == rp0
    assert up[gd2 * GEN] == rp1
    rn0 = upq[gd2]
    rn1 = upq[gd2 * GEN]

    # ---- 9: the attempt key, K = H(succ-cell || v || R_prev), or at attempt a > 0 H(succ-attempt || that || a) ----
    sc = HeapBuf(172)
    for i in unroll(0, len(TAG_SUCC_CELL)):
        sc[GEN ** (2 * i)] = const(TAG_SUCC_CELL[i] % 16)
        sc[GEN ** (2 * i + 1)] = const(TAG_SUCC_CELL[i] // 16)
    sc[GEN ** 42] = 0
    sc[GEN ** 43] = 0
    put_value(sc, 22, vp)
    put_value(sc, 54, rpp)
    base_key = hash_msg(sc, 86)
    # The attempt's 8 big-endian bytes, the first of a 32-byte value.
    a_lo = 0
    for j in unroll(0, 8):
        a_lo = a_lo + (nib[attempt[GEN ** (14 - 2 * j)]] + nib[attempt[GEN ** (15 - 2 * j)]] * GEN ** 4) * GEN ** (8 * j)
    ab = StackBuf(2)
    ab[0] = a_lo
    ab[1] = 0
    am = StackBuf(4)
    for c in unroll(0, 4):
        am[c] = attempt_m[GEN ** c]
    ivc = StackBuf(2)
    ivc[0] = B3_IV0
    ivc[1] = B3_IV1
    zc = StackBuf(2)
    zc[0] = 0
    zc[1] = 0
    at1 = StackBuf(2)
    blake3(am[0:2], am[2:4], ivc, MD_64_START, at1, x=base_key, y=ab)
    attempt_key = StackBuf(2)
    blake3(zc, zc, at1, MD_1_END, attempt_key, w=ab)
    is_zero = hint_witness("attempt_is_zero")
    assert is_zero * is_zero == is_zero
    a_val = int_limb(attempt, nib, 16)
    assert is_zero * a_val == 0
    assert a_val + is_zero != 0
    k0 = attempt_key[0] + is_zero * (base_key[0] + attempt_key[0])
    k1 = attempt_key[1] + is_zero * (base_key[1] + attempt_key[1])

    # ---- the statement: H(stmt || v || R_prev || R_next || u64be(g) || E || K) is the public input ----
    rnp, rnd = value_nibbles(rn0, rn1, nib)
    kp, kd = value_nibbles(k0, k1, nib)
    st = HeapBuf(400)
    for i in unroll(0, len(TAG_STATEMENT)):
        st[GEN ** (2 * i)] = const(TAG_STATEMENT[i] % 16)
        st[GEN ** (2 * i + 1)] = const(TAG_STATEMENT[i] // 16)
    st[GEN ** 62] = 0
    st[GEN ** 63] = 0
    put_value(st, 32, vp)
    put_value(st, 64, rpp)
    put_value(st, 96, rnp)
    put_u64_be(st, 128, generation2, nib)
    put_value(st, 136, ep)
    put_value(st, 168, kp)
    statement = hash_msg(st, 200)
    public = GEN ** 0
    public[1] = statement[0]
    public[GEN] = statement[1]
    return
