#!/usr/bin/env python3
"""Issue coding-ledger Pro licenses.

The private key never enters the repository. Keep it at
~/.coding-ledger/license_signing_key (or pass --key).

  python3 tools/sign_license.py keygen
      Generate a signing key and print the public key hex to embed in
      coding_ledger.py as LICENSE_PUBKEY_HEX.

  python3 tools/sign_license.py issue --email buyer@example.com \
      [--plan pro] [--expires 2027-07-28] [--key PATH]
      Print a license string to deliver to the buyer. They run:
      coding-ledger license install '<string>'
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import coding_ledger as cl  # noqa: E402  (vendored curve math lives there)

DEFAULT_KEY = Path.home() / ".coding-ledger" / "license_signing_key"


def _clamp_scalar(digest32: bytes) -> int:
    a = int.from_bytes(digest32, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    return cl._ed_encodepoint(cl._ed_scalarmult(cl._ED_B, _clamp_scalar(digest[:32])))


def sign(message: bytes, seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    a = _clamp_scalar(digest[:32])
    pub = cl._ed_encodepoint(cl._ed_scalarmult(cl._ED_B, a))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little")
    point_r = cl._ed_encodepoint(cl._ed_scalarmult(cl._ED_B, r))
    h = int.from_bytes(hashlib.sha512(point_r + pub + message).digest(), "little")
    s = (r + h * a) % cl._ED_L
    return point_r + s.to_bytes(32, "little")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_license(seed: bytes, email: str, plan: str,
                 expires: str | None, issued: str | None = None) -> str:
    payload = {"v": 1, "email": email, "plan": plan,
               "issued": issued or datetime.now().astimezone().strftime("%Y-%m-%d"),
               "expires": expires}
    payload_bytes = json.dumps(payload, separators=(",", ":"),
                               sort_keys=True).encode()
    return f"{_b64url(payload_bytes)}.{_b64url(sign(payload_bytes, seed))}"


def cmd_keygen(args) -> None:
    key_path = Path(args.key)
    if key_path.exists() and not args.force:
        sys.exit(f"refusing to overwrite {key_path} (pass --force)")
    seed = os.urandom(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(seed.hex() + "\n")
    key_path.chmod(0o600)
    print(f"signing key written to {key_path}")
    print(f"embed in coding_ledger.py: LICENSE_PUBKEY_HEX = \"{public_key(seed).hex()}\"")


def cmd_issue(args) -> None:
    key_path = Path(args.key)
    try:
        seed = bytes.fromhex(key_path.read_text().strip())
    except (OSError, ValueError):
        sys.exit(f"cannot read signing key at {key_path} (run keygen first)")
    if len(seed) != 32:
        sys.exit("signing key must be 32 bytes of hex")
    license_text = make_license(seed, args.email, args.plan, args.expires)
    state = cl.license_state(license_text, pubkey_hex=public_key(seed).hex())
    if state["status"] != "valid":
        sys.exit(f"self-check failed: {state['status']}")
    print(license_text)


def main() -> None:
    ap = argparse.ArgumentParser(prog="sign_license")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="generate the signing keypair")
    p.add_argument("--key", default=str(DEFAULT_KEY))
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("issue", help="issue a license string")
    p.add_argument("--email", required=True)
    p.add_argument("--plan", default="pro")
    p.add_argument("--expires", help="YYYY-MM-DD; omit for lifetime")
    p.add_argument("--key", default=str(DEFAULT_KEY))
    p.set_defaults(fn=cmd_issue)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
