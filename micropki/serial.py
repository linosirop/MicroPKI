from __future__ import annotations

import secrets
import time


def generate_unique_serial_int() -> int:
    """
    64-bit composite serial:
    high 32 bits = current Unix timestamp (seconds)
    low 32 bits = cryptographically secure random value

    Result is always positive and practically unique.
    """
    ts = int(time.time()) & 0xFFFFFFFF
    rnd = secrets.randbits(32) & 0xFFFFFFFF
    serial = (ts << 32) | rnd

    if serial <= 0:
        serial = 1

    return serial


def serial_int_to_hex(serial: int) -> str:
    return format(serial, "X")