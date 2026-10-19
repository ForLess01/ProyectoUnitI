"""One-request HTTP bridge used only over docker exec stdin/stdout."""

from __future__ import annotations

import socket
import sys


MAX_REQUEST_BYTES = 131_072
MAX_RESPONSE_BYTES = 1_048_576


def main() -> int:
    request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not request or len(request) > MAX_REQUEST_BYTES:
        return 2
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", 8765), timeout=10) as connection:
            connection.settimeout(10)
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            while True:
                chunk = connection.recv(16_384)
                if not chunk:
                    break
                if len(response) + len(chunk) > MAX_RESPONSE_BYTES:
                    return 3
                response.extend(chunk)
    except OSError:
        return 4
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
