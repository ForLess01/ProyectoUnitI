"""Non-production credentials and RFC 6238 test vectors for the local lab."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


DEMO_PASSWORDS = {
    "lucia": "U7-lab-Reader!2026",
    "mateo": "U7-lab-Editor!2026",
    "ana.admin": "U7-lab-Admin!2026",
}

# RFC 6238 Appendix B SHA-1 test secret; public, synthetic, and unsuitable for use
# outside this disposable demonstration.
RFC6238_SECRET = b"12345678901234567890"
RFC6238_SECRET_BASE32 = base64.b32encode(RFC6238_SECRET).decode("ascii").rstrip("=")


def totp_code(secret: bytes = RFC6238_SECRET, timestamp: float | None = None) -> str:
    """Return a six-digit SHA-1 TOTP using the RFC 6238 30-second time step."""
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // 30)
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"
