from __future__ import annotations

import re
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

from micropki.database import get_certificate_by_serial


HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def make_repository_handler(db_path: str, cert_dir: str, logger):
    cert_dir_path = Path(cert_dir)

    class RepositoryHandler(BaseHTTPRequestHandler):
        def _send_text(self, code: int, text: str, content_type: str = "text/plain") -> None:
            data = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def _log_http(self, status_code: int) -> None:
            client_ip = self.client_address[0] if self.client_address else "-"
            logger.info(
                f"[HTTP] {self.command} {self.path} client={client_ip} status={status_code}"
            )

        def do_GET(self):
            try:
                if self.path.startswith("/certificate/"):
                    serial_hex = self.path.removeprefix("/certificate/").strip()

                    if not serial_hex or not HEX_RE.fullmatch(serial_hex):
                        self._send_text(400, "Invalid serial format")
                        self._log_http(400)
                        return

                    row = get_certificate_by_serial(db_path, serial_hex)
                    if row is None:
                        self._send_text(404, "Certificate not found")
                        self._log_http(404)
                        return

                    self._send_text(200, row["cert_pem"], "application/x-pem-file")
                    self._log_http(200)
                    return

                if self.path == "/ca/root":
                    root_path = cert_dir_path / "ca.cert.pem"
                    if not root_path.exists():
                        self._send_text(404, "Root CA certificate not found")
                        self._log_http(404)
                        return

                    self._send_text(200, root_path.read_text(encoding="utf-8"), "application/x-pem-file")
                    self._log_http(200)
                    return

                if self.path == "/ca/intermediate":
                    intermediate_path = cert_dir_path / "intermediate.cert.pem"
                    if not intermediate_path.exists():
                        self._send_text(404, "Intermediate CA certificate not found")
                        self._log_http(404)
                        return

                    self._send_text(
                        200,
                        intermediate_path.read_text(encoding="utf-8"),
                        "application/x-pem-file",
                    )
                    self._log_http(200)
                    return

                if self.path == "/crl":
                    self._send_text(501, "CRL generation not yet implemented", "text/plain")
                    self._log_http(501)
                    return

                self._send_text(404, "Not Found")
                self._log_http(404)

            except Exception as e:
                logger.error(f"[HTTP] Internal server error: {e}")
                self._send_text(500, "Internal Server Error")
                self._log_http(500)

        def do_POST(self):
            self._send_text(405, "Method Not Allowed")
            self._log_http(405)

        def do_PUT(self):
            self._send_text(405, "Method Not Allowed")
            self._log_http(405)

        def do_DELETE(self):
            self._send_text(405, "Method Not Allowed")
            self._log_http(405)

        def log_message(self, format, *args):
            return

    return RepositoryHandler


def serve_repository(host: str, port: int, db_path: str, cert_dir: str, logger) -> None:
    handler = make_repository_handler(db_path, cert_dir, logger)
    server = HTTPServer((host, port), handler)

    logger.info(f"[HTTP] Repository server started on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[HTTP] Repository server stopped by user")
    finally:
        server.server_close()