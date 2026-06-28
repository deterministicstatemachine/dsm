#!/usr/bin/env python3
"""Host-side driver for the DSM Boot Fenced Fused Anchor USB appliance protocol.

Speaks the firmware's wire format (proto/dsm_anchor.proto over a little-endian
u32 length prefix). protobuf is hand-encoded/decoded here (no deps) so this also
serves as a minimal reference for any host driver. The device boot-fences itself
at startup, so this drives one full fused root advance:

    STATUS -> PREPARE -> COMMIT -> EMIT -> FINALIZE -> STATUS

checking the 3-state machine (Ready -> Prepared -> Committed -> Ready), that a
release is emitted only after commit, and that finalize advances the active root.
The witness / partition-cert / DSM proofs are verified by a real receiver, not here.
"""

import glob
import os
import select
import sys
import termios
import time

# --- minimal protobuf wire codec ---


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field, wire):
    return varint((field << 3) | wire)


def uint_f(field, n):
    return tag(field, 0) + varint(n)


def bytes_f(field, data):
    return tag(field, 2) + varint(len(data)) + data


def read_varint(b, i):
    n = 0
    s = 0
    while True:
        x = b[i]
        i += 1
        n |= (x & 0x7F) << s
        if not x & 0x80:
            return n, i
        s += 7


def parse(body):
    i = 0
    out = {}
    while i < len(body):
        t, i = read_varint(body, i)
        field, wire = t >> 3, t & 7
        if wire == 0:
            v, i = read_varint(body, i)
            out[field] = v
        elif wire == 2:
            ln, i = read_varint(body, i)
            out[field] = body[i:i + ln]
            i += ln
        else:
            raise ValueError(f"unexpected wire type {wire}")
    return out


# --- request builders (field numbers from dsm_anchor.proto) ---

# Boot is device-internal (the device boot-fences itself at startup); value 1 is
# reserved and there is no host-reachable boot op.
OP_PREPARE, OP_COMMIT, OP_EMIT, OP_FINALIZE, OP_STATUS, OP_CANCEL = 2, 3, 4, 5, 6, 7

GENESIS = b"\x00" * 32
NEXT_ROOT = b"\x11" * 32
POLICY = b"\xB0" * 32
RCHAL = b"\x55" * 32


def op_req(op):
    return uint_f(1, op)


def prepare_req():
    tr = b"".join([
        bytes_f(1, b"\x01" * 32),    # relationship_id
        bytes_f(2, b"\x02" * 32),    # object_id
        bytes_f(3, b"\x03" * 32),    # sender_device_id
        bytes_f(4, b"\x04" * 32),    # recipient_device_id
        bytes_f(5, GENESIS),         # prev_root (active root, anchor counter 0)
        bytes_f(6, NEXT_ROOT),       # next_root
        # anchor_counter = 0 (proto3 default -> omitted)
        uint_f(8, 1),                # next_anchor_counter = 1
        # action_type = 0 (Transfer) is the proto3 default -> omitted
        bytes_f(10, b"\xAA\xBB"),    # action_fields
        bytes_f(11, b"\x09" * 32),   # payload_hash
        bytes_f(12, b"\xAB" * 40),   # old_leaf_proof
        bytes_f(13, b"\xCD" * 40),   # new_leaf_proof
        bytes_f(14, POLICY),         # authority_policy_hash
    ])
    return uint_f(1, OP_PREPARE) + bytes_f(2, tr) + bytes_f(3, RCHAL)


# --- transport: LE32 length-prefixed frames over USB-CDC ---


def open_port():
    t0 = time.time()
    ports = []
    while time.time() - t0 < 20:
        ports = glob.glob("/dev/cu.usbmodem*")
        if ports:
            break
        time.sleep(0.5)
    if not ports:
        print("no serial port found")
        sys.exit(1)
    fd = os.open(ports[0], os.O_RDWR | os.O_NOCTTY)
    attrs = termios.tcgetattr(fd)
    attrs[0] = attrs[1] = attrs[3] = 0  # iflag, oflag, lflag = raw
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return ports[0], fd


def read_until_quiet(fd, max_wait, quiet=2.5):
    """Drain the boot log until it goes quiet (the serve loop emits no unsolicited
    output, so quiescence marks that serving has started). The firmware's log
    writes are non-blocking and may drop bytes when no reader is attached."""
    dl = time.time() + max_wait
    buf = b""
    last = time.time()
    while time.time() < dl:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                got = os.read(fd, 1024)
            except OSError:
                got = b""
            if got:
                buf += got
                last = time.time()
        if time.time() - last >= quiet:
            break
    return buf


def read_n(fd, n, timeout):
    dl = time.time() + timeout
    buf = b""
    while len(buf) < n and time.time() < dl:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                buf += os.read(fd, n - len(buf))
            except OSError:
                pass
    return buf


def call(fd, body, timeout=8):
    frame = len(body).to_bytes(4, "little") + body
    os.write(fd, frame)
    hdr = read_n(fd, 4, timeout)
    if len(hdr) < 4:
        raise TimeoutError("no response length")
    rlen = int.from_bytes(hdr, "little")
    resp = read_n(fd, rlen, timeout)
    if len(resp) < rlen:
        raise TimeoutError("short response body")
    return parse(resp)


def status(s):
    # response fields: ok=2, error=3, active_root=5, active_anchor_counter=9,
    # status=10 (0=Ready 1=Prepared 2=Committed), boot_valid=11
    return {
        "ok": s.get(2, 0),
        "error": s.get(3, 0),
        "counter": s.get(9, 0),
        "status": s.get(10, 0),
        "boot_valid": s.get(11, 0),
    }


def main():
    port, fd = open_port()
    print("PORT:", port)
    boot = read_until_quiet(fd, 30)
    sys.stdout.write(boot.decode("ascii", "replace"))
    if b"[T5] PASS" not in boot:
        print("\nWARN: did not observe [T5] PASS in the (lossy) boot log; trying anyway")
    print("\n---- driving one fused root advance over USB (device self-boot-fenced) ----")

    st0 = call(fd, op_req(OP_STATUS))
    print("STATUS#1:", status(st0))

    prep = call(fd, prepare_req())
    print("PREPARE :", {"ok": prep.get(2, 0), "error": prep.get(3, 0)})

    st1 = call(fd, op_req(OP_STATUS))
    print("STATUS#2:", status(st1))

    com = call(fd, op_req(OP_COMMIT))
    print("COMMIT  :", {"ok": com.get(2, 0), "error": com.get(3, 0)})

    emit = call(fd, op_req(OP_EMIT))
    print("EMIT    :", {"ok": emit.get(2, 0), "error": emit.get(3, 0),
                        "release_bytes": len(emit.get(4, b""))})

    fin = call(fd, op_req(OP_FINALIZE))
    fin_root = fin.get(5, b"")
    print("FINALIZE:", {"ok": fin.get(2, 0), "active_root_ok": fin_root == NEXT_ROOT})

    st2 = call(fd, op_req(OP_STATUS))
    print("STATUS#3:", status(st2))

    ok = (
        st0.get(2, 0) == 1 and st0.get(9, 0) == 0 and st0.get(10, 0) == 0 and st0.get(11, 0) == 1
        and prep.get(2, 0) == 1
        and st1.get(2, 0) == 1 and st1.get(10, 0) == 1                  # Prepared
        and com.get(2, 0) == 1
        and emit.get(2, 0) == 1 and len(emit.get(4, b"")) > 0           # release after commit
        and fin.get(2, 0) == 1 and fin_root == NEXT_ROOT               # advanced to hi+1
        and st2.get(2, 0) == 1 and st2.get(10, 0) == 0 and st2.get(9, 0) == 1  # Ready, counter 1
    )
    print("RESULT:", "PASS — external host drove a fused root advance over USB" if ok else "FAIL")
    os.close(fd)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
