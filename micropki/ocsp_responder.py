from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import load_der_ocsp_request

from micropki.logger import setup_logger
from micropki.ocsp import build_ocsp_response


def make_ocsp_handler(db_path: str, responder_cert_path: str, responder_key_path: str,
                      ca_cert_path: str, cache_ttl: int, logger):
    responder_cert = x509.load_pem_x509_certificate(Path(responder_cert_path).read_bytes())
    responder_key = serialization.load_pem_private_key(
        Path(responder_key_path).read_bytes(), password=None
    )
    issuer_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())

    class OCSPHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "MicroPKI-OCSP/1.0"

        def do_GET(self):
            """Простой healthcheck"""
            try:
                if self.path in ("/", "/health", "/status", "/ocsp"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"OCSP Responder is running\n")
                    return
            except Exception as e:
                logger.error(f"Error in do_GET: {e}")

            self.send_error(404, "Not Found")

        def do_POST(self):
            start_time = time.time()
            client_ip = self.client_address[0]

            if self.path not in ("/ocsp", "/"):
                self.send_error(404, "Not Found")
                return

            try:
                content_type = self.headers.get('Content-Type', '')
                if 'application/ocsp-request' not in content_type:
                    self.send_error(400, "Bad Request: wrong Content-Type")
                    return

                length = int(self.headers.get('Content-Length', 0))
                if length <= 0:
                    # Возвращаем malformedRequest вместо ошибки
                    error_response = b'\x30\x03\x0A\x01\x02'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/ocsp-response")
                    self.send_header("Content-Length", str(len(error_response)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(error_response)
                    return

                der_request = self.rfile.read(length)

                # Основная обработка
                ocsp_req = load_der_ocsp_request(der_request)

                response_der = build_ocsp_response(
                    ocsp_req, db_path, issuer_cert, responder_cert, responder_key, cache_ttl
                )

                self.send_response(200)
                self.send_header("Content-Type", "application/ocsp-response")
                self.send_header("Content-Length", str(len(response_der)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_der)

                duration = int((time.time() - start_time) * 1000)
                serial = f"{ocsp_req.serial_number:x}" if hasattr(ocsp_req, 'serial_number') else "multi"
                logger.info(f"OCSP OK | {client_ip} | serial={serial} | {duration}ms")

            except Exception as e:
                logger.error(f"OCSP error from {client_ip}: {e}", exc_info=True)
                error_response = b'\x30\x03\x0A\x01\x02'

                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/ocsp-response")
                    self.send_header("Content-Length", str(len(error_response)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(error_response)
                except:
                    self.send_error(500, "Internal Server Error")

    return OCSPHandler


def serve_ocsp(host: str, port: int, db_path: str, responder_cert: str,
               responder_key: str, ca_cert: str, cache_ttl: int, logger):
    handler = make_ocsp_handler(db_path, responder_cert, responder_key, ca_cert, cache_ttl, logger)

    server = ThreadingHTTPServer((host, port), handler)
    server.allow_reuse_address = True

    logger.info(f"OCSP Responder started on http://{host}:{port}/ocsp")
    print(f"🚀 OCSP Responder listening on http://{host}:{port}/ocsp")
    print("   Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("OCSP Responder stopped by user")
        print("\n🛑 OCSP Responder stopped.")
    finally:
        server.server_close()