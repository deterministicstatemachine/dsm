#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Assemble the public storage set from the five operators' codes. The owner runs this.

    assemble_public_set.py add <code> [--replace]   Check one operator's code against their live node, and keep it.
    assemble_public_set.py status                   Say which seats are in.
    assemble_public_set.py build                    With all five: write the member list and the app's pins.
    assemble_public_set.py check                    After publishing: ask every node to reach every other.

Everything handled here is public: no operator's key ever leaves their machine.
Kept in ~/.dsm-public-beta, or the directory DSM_PUBLIC_SET_DIR names.
"""

import argparse
import base64
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SEATS = range(1, 6)
CODE_PREFIX = "DSMNODE1:"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
HOME = Path(os.environ.get("DSM_PUBLIC_SET_DIR", Path.home() / ".dsm-public-beta"))
RELEASE_TAG = "public-beta-set"
REPOSITORY = "deterministicstatemachine/dsm"
ONE_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,76}\n)+-----END CERTIFICATE-----\n")


def fail(message: str) -> None:
    sys.exit(f"Refused: {message}")


def crockford_to_bytes(text: str) -> bytes:
    """The 32 bytes of a Base32-Crockford register incarnation."""
    bits = 0
    held = 0
    out = bytearray()
    for character in text:
        position = CROCKFORD.find(character)
        if position < 0:
            fail(f"'{character}' is not Base32-Crockford")
        bits = (bits << 5) | position
        held += 5
        if held >= 8:
            held -= 8
            out.append((bits >> held) & 0xFF)
    if len(out) != 32 or bits & ((1 << held) - 1):
        fail(f"{text} is not 32 bytes of Base32-Crockford")
    return bytes(out)


def decode_code(code: str) -> dict:
    code = re.sub(r"\s", "", code)
    if not code.startswith(CODE_PREFIX):
        fail(f"a code starts with {CODE_PREFIX}")
    try:
        body = json.loads(gzip.decompress(base64.b64decode(code[len(CODE_PREFIX):], validate=True)))
    except (ValueError, OSError) as error:
        fail(f"this code is damaged or cut off: {error}")
    for field in ("seat", "endpoint", "register_incarnation", "ca_cert"):
        if field not in body:
            fail(f"this code has no {field}")
    if body["seat"] not in SEATS:
        fail(f"seat {body['seat']} is not 1 to 5")
    if not re.fullmatch(r"https://\d+\.\d+\.\d+\.\d+:8080", body["endpoint"]):
        fail(f"{body['endpoint']} is not https://<IP>:8080")
    crockford_to_bytes(body["register_incarnation"])
    # A code comes from outside, and its text ends up inside the app's env config
    # and every node's settings: exactly one certificate, and nothing around it.
    if not isinstance(body["ca_cert"], str) or not ONE_CERTIFICATE.fullmatch(body["ca_cert"]):
        fail("this code's certificate is not exactly one PEM certificate")
    return body


def run(*command: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, input=stdin, capture_output=True, timeout=30, check=False)


def member_id(seat: int) -> str:
    return f"dsm-node-{seat}"


def verify_live(body: dict) -> None:
    """The node at this address serves a certificate from this code's CA, naming this seat."""
    host_port = body["endpoint"].removeprefix("https://")
    with tempfile.TemporaryDirectory() as directory:
        ca = Path(directory, "ca.crt")
        ca.write_text(body["ca_cert"])
        served = run("openssl", "s_client", "-connect", host_port, "-CAfile", str(ca),
                     "-verify_hostname", member_id(body["seat"]), "-verify_return_error", stdin=b"")
        if served.returncode != 0 or b"Verification: OK" not in served.stdout:
            fail(f"the node at {host_port} is not serving seat {body['seat']} under this code's CA. "
                 "Is it running, and is its port open?")
        health = run("curl", "-fsS", "--max-time", "15", "--cacert", str(ca), f"{body['endpoint']}/api/v2/health")
        if health.returncode != 0:
            fail(f"the node at {host_port} did not answer its health check: {health.stderr.decode().strip()}")


def seat_file(seat: int) -> Path:
    return HOME / "seats" / f"{seat}.json"


def held_seats() -> dict[int, dict]:
    return {seat: json.loads(seat_file(seat).read_text()) for seat in SEATS if seat_file(seat).exists()}


def add(arguments: argparse.Namespace) -> None:
    body = decode_code(arguments.code)
    seat = body["seat"]
    if seat_file(seat).exists() and not arguments.replace:
        held = json.loads(seat_file(seat).read_text())
        if held == body:
            print(f"Seat {seat} is already in, with this same code.")
            return
        fail(f"seat {seat} already holds a different code. Only someone you assigned this seat "
             "to should have sent one. If they rebuilt their node, repeat with --replace.")
    for other, held in held_seats().items():
        if other != seat and held["endpoint"] == body["endpoint"]:
            fail(f"seat {other} is already at {body['endpoint']}")
        if other != seat and held["register_incarnation"] == body["register_incarnation"]:
            fail(f"seat {other} already holds this register incarnation")
    verify_live(body)
    seat_file(seat).parent.mkdir(parents=True, exist_ok=True)
    seat_file(seat).write_text(json.dumps(body, indent=2) + "\n")
    print(f"Seat {seat} is in: {body['endpoint']}")
    show_status()


def show_status() -> None:
    held = held_seats()
    for seat in SEATS:
        print(f"  seat {seat}: {held[seat]['endpoint'] if seat in held else 'waiting for their code'}")
    if len(held) == len(SEATS):
        print("All five are in. Next: assemble_public_set.py build")


def rust_pins(held: dict[int, dict]) -> str:
    lines = [
        "// dsm_client/deterministic_state_machine/dsm/src/economic/register.rs",
        "const BETA_ROOT_REGISTER_MEMBERS: [PinnedMember; 5] = [",
    ]
    for seat in SEATS:
        pin = crockford_to_bytes(held[seat]["register_incarnation"])
        lines += ["    (", f'        b"{member_id(seat)}",', "        ["]
        lines += ["            " + ", ".join(f"0x{b:02X}" for b in pin[i:i + 14]) + "," for i in range(0, 32, 14)]
        lines += ["        ],", "    ),"]
    lines += ["];", "", "// The incarnations as dsm_sdk/src/sdk/storage_set.rs renders them:"]
    lines += [f'// "{member_id(seat)}": "{held[seat]["register_incarnation"]}"' for seat in SEATS]
    return "\n".join(lines) + "\n"


def env_config_nodes(held: dict[int, dict]) -> str:
    return "".join(
        f'[[nodes]]\nname = "{member_id(seat)}"\nendpoint = "{held[seat]["endpoint"]}"\n'
        f'register_incarnation = "{held[seat]["register_incarnation"]}"\n'
        f'ca_cert = """\n{held[seat]["ca_cert"]}"""\n\n'
        for seat in SEATS
    )


def build(_: argparse.Namespace) -> None:
    held = held_seats()
    missing = [seat for seat in SEATS if seat not in held]
    if missing:
        fail(f"still waiting for seats {missing}")
    members = [
        {
            "id": member_id(seat),
            "register_incarnation": held[seat]["register_incarnation"],
            "endpoint": held[seat]["endpoint"],
            "ca_cert": held[seat]["ca_cert"],
        }
        for seat in SEATS
    ]
    out = HOME / "public"
    out.mkdir(parents=True, exist_ok=True)
    listing = out / "public_beta_set.json"
    listing.write_text(json.dumps({"members": members}, indent=2) + "\n")
    (out / "dsm_env_config.nodes.toml").write_text(env_config_nodes(held))
    (out / "core_pins.txt").write_text(rust_pins(held))
    print(f"""Written to {out}

1. Publish the member list. Every node takes it within five minutes, once, by itself.
   It cannot change afterwards: the set is immutable.

   gh release create {RELEASE_TAG} --repo {REPOSITORY} --title "Public beta storage set" \\
     --notes "The members of the public beta storage set." "{listing}"

2. Confirm all five reached each other:

   python3 {Path(__file__).name} check

3. Build the public app with these pins:
   - dsm_env_config.nodes.toml replaces the [[nodes]] entries of the app's env config.
   - core_pins.txt replaces BETA_ROOT_REGISTER_MEMBERS, and the values in storage_set.rs.
""")


def check(_: argparse.Namespace) -> None:
    """Each node mirrors every set-mate on request: 204 means it reached all four, each under its own CA."""
    held = held_seats()
    bad = 0
    for seat, body in sorted(held.items()):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory, "ca.crt")
            ca.write_text(body["ca_cert"])
            answer = run("curl", "-sS", "--max-time", "25", "--cacert", str(ca), "-X", "POST",
                         "-o", "/dev/null", "-w", "%{http_code}",
                         f"{body['endpoint']}/api/v2/bytecommit/mirror/sync")
        code = answer.stdout.decode().strip()
        meaning = {
            "204": "reached every other node",
            "409": "has not taken the member list yet",
            "502": "could not reach at least one other node",
        }.get(code, f"answered {code or answer.stderr.decode().strip()}")
        print(f"  seat {seat}: {meaning}")
        bad += code != "204"
    if len(held) != len(SEATS):
        print(f"Only {len(held)} of 5 seats are in.")
        bad += 1
    if bad:
        sys.exit(1)
    print("All five nodes reached each other.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    adding = commands.add_parser("add")
    adding.add_argument("code")
    adding.add_argument("--replace", action="store_true")
    adding.set_defaults(run=add)
    commands.add_parser("status").set_defaults(run=lambda _: show_status())
    commands.add_parser("build").set_defaults(run=build)
    commands.add_parser("check").set_defaults(run=check)
    arguments = parser.parse_args()
    arguments.run(arguments)


if __name__ == "__main__":
    main()
