from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from micropki.ca import (
    init_root_ca,
    issue_intermediate_ca,
    issue_end_entity_certificate,
    issue_ocsp_responder_certificate,
    show_certificate_from_db,
    list_certificates_from_db,
    revoke_certificate_via_cli,
    generate_crl_via_cli,
)
from micropki.logger import setup_logger
from micropki.certificates import parse_subject_dn
from micropki.database import init_database
from micropki.repository import serve_repository
from micropki.ocsp_responder import serve_ocsp
from micropki.revocation import SUPPORTED_REVOCATION_REASONS
from micropki.audit import init_audit_logger, get_audit_logger
from micropki.policy import MAX_VALIDITY, MIN_KEY_SIZE
from micropki.transparency import CTLog
from micropki.compromise import mark_key_compromised, get_public_key_hash

DEFAULT_DB_PATH = "./pki/micropki.db"


def validate_writable_directory(path_str: str) -> None:
    path = Path(path_str)
    parent_dir = path if path.exists() else path.parent
    if not parent_dir.exists():
        parent_dir = Path(".")
    if not os.access(parent_dir, os.W_OK):
        raise ValueError(f"Directory is not writable: {path_str}")


def validate_args(args: argparse.Namespace) -> None:
    if args.command == "db":
        if args.db_command == "init":
            validate_writable_directory(args.db_path)
        return

    if args.command == "repo":
        if args.repo_command == "serve":
            validate_writable_directory(args.db_path)
            if args.port <= 0 or args.port > 65535:
                raise ValueError("--port must be between 1 and 65535")
        return

    if args.command == "ocsp":
        if args.ocsp_command == "serve":
            validate_writable_directory(args.db_path)
            for f in (args.responder_cert, args.responder_key, args.ca_cert):
                if not Path(f).is_file():
                    raise ValueError(f"File not found: {f}")
            if args.port <= 0 or args.port > 65535:
                raise ValueError("--port must be between 1 and 65535")
        return

    if args.command != "ca":
        return

    if args.ca_command == "init":
        if not args.subject or not args.subject.strip():
            raise ValueError("--subject must be a non-empty string")
        parse_subject_dn(args.subject)
        if args.key_type == "rsa" and args.key_size != 4096:
            raise ValueError("For RSA, --key-size must be 4096")
        if args.key_type == "ecc" and args.key_size != 384:
            raise ValueError("For ECC, --key-size must be 384")
        if args.validity_days <= 0:
            raise ValueError("--validity-days must be a positive integer")
        if not Path(args.passphrase_file).is_file():
            raise ValueError("--passphrase-file must exist and be a readable file")
        validate_writable_directory(args.out_dir)

    elif args.ca_command == "issue-intermediate":
        parse_subject_dn(args.subject)
        if args.key_type == "rsa" and args.key_size != 4096:
            raise ValueError("For RSA, --key-size must be 4096")
        if args.key_type == "ecc" and args.key_size != 384:
            raise ValueError("For ECC, --key-size must be 384")
        if args.validity_days <= 0:
            raise ValueError("--validity-days must be positive")
        if args.pathlen < 0:
            raise ValueError("--pathlen must be non-negative")
        for file_arg in (args.root_cert, args.root_key, args.root_pass_file, args.passphrase_file):
            if not Path(file_arg).is_file():
                raise ValueError(f"Missing required file: {file_arg}")
        validate_writable_directory(args.out_dir)

    elif args.ca_command in ("issue-cert", "issue-ocsp-cert"):
        parse_subject_dn(args.subject)
        if args.validity_days <= 0:
            raise ValueError("--validity-days must be positive")
        for file_arg in (args.ca_cert, args.ca_key, args.ca_pass_file):
            if not Path(file_arg).is_file():
                raise ValueError(f"Missing required file: {file_arg}")
        validate_writable_directory(args.out_dir)

    elif args.ca_command == "show-cert":
        if not args.serial:
            raise ValueError("Serial must be provided")

    elif args.ca_command == "list-certs":
        if args.status and args.status not in {"valid", "revoked", "expired"}:
            raise ValueError("--status must be one of: valid, revoked, expired")
        if args.format not in {"table", "json", "csv"}:
            raise ValueError("--format must be one of: table, json, csv")

    elif args.ca_command == "revoke":
        if not args.serial:
            raise ValueError("Serial must be provided")
        if args.reason.strip().lower() not in SUPPORTED_REVOCATION_REASONS:
            raise ValueError(f"Unsupported revocation reason: {args.reason}")

    elif args.ca_command == "gen-crl":
        if args.ca not in {"root", "intermediate"}:
            raise ValueError("--ca must be either 'root' or 'intermediate'")
        if args.next_update <= 0:
            raise ValueError("--next-update must be positive")
        if not Path(args.passphrase_file).is_file():
            raise ValueError("--passphrase-file must exist and be readable")
        validate_writable_directory(args.out_dir)

    elif args.ca_command == "audit-query":
        if args.format not in {"table", "json", "csv"}:
            raise ValueError("--format must be one of: table, json, csv")

    elif args.ca_command == "compromise":
        if not Path(args.cert).is_file():
            raise ValueError(f"Certificate file not found: {args.cert}")

    elif args.ca_command == "ct-verify":
        if not args.serial:
            raise ValueError("Serial must be provided")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="micropki")
    subparsers = parser.add_subparsers(dest="command")

    # db
    db_parser = subparsers.add_parser("db")
    db_subparsers = db_parser.add_subparsers(dest="db_command")
    db_init_parser = db_subparsers.add_parser("init")
    db_init_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    db_init_parser.add_argument("--log-file", default=None, type=str)

    # repo
    repo_parser = subparsers.add_parser("repo")
    repo_subparsers = repo_parser.add_subparsers(dest="repo_command")
    repo_serve_parser = repo_subparsers.add_parser("serve")
    repo_serve_parser.add_argument("--host", default="127.0.0.1", type=str)
    repo_serve_parser.add_argument("--port", default=8080, type=int)
    repo_serve_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    repo_serve_parser.add_argument("--cert-dir", default="./pki/certs", type=str)
    repo_serve_parser.add_argument("--log-file", default=None, type=str)
    repo_serve_parser.add_argument("--rate-limit", default=0, type=float,
                                   help="Requests per second per client IP (0 = disabled)")
    repo_serve_parser.add_argument("--rate-burst", default=10, type=int,
                                   help="Burst allowance")

    # ocsp
    ocsp_parser = subparsers.add_parser("ocsp")
    ocsp_subparsers = ocsp_parser.add_subparsers(dest="ocsp_command")
    ocsp_serve_parser = ocsp_subparsers.add_parser("serve")
    ocsp_serve_parser.add_argument("--host", default="127.0.0.1", type=str)
    ocsp_serve_parser.add_argument("--port", default=8081, type=int)
    ocsp_serve_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    ocsp_serve_parser.add_argument("--responder-cert", required=True, type=str)
    ocsp_serve_parser.add_argument("--responder-key", required=True, type=str)
    ocsp_serve_parser.add_argument("--ca-cert", required=True, type=str)
    ocsp_serve_parser.add_argument("--cache-ttl", default=60, type=int)
    ocsp_serve_parser.add_argument("--log-file", default=None, type=str)

    # ca
    ca_parser = subparsers.add_parser("ca")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command")

    init_parser = ca_subparsers.add_parser("init")
    init_parser.add_argument("--subject", required=True, type=str)
    init_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_parser.add_argument("--key-size", type=int, required=True)
    init_parser.add_argument("--passphrase-file", required=True, type=str)
    init_parser.add_argument("--out-dir", default="./pki", type=str)
    init_parser.add_argument("--validity-days", default=3650, type=int)
    init_parser.add_argument("--db-path", default=None, type=str)
    init_parser.add_argument("--log-file", default=None, type=str)

    intermediate_parser = ca_subparsers.add_parser("issue-intermediate")
    intermediate_parser.add_argument("--root-cert", required=True, type=str)
    intermediate_parser.add_argument("--root-key", required=True, type=str)
    intermediate_parser.add_argument("--root-pass-file", required=True, type=str)
    intermediate_parser.add_argument("--subject", required=True, type=str)
    intermediate_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    intermediate_parser.add_argument("--key-size", type=int, required=True)
    intermediate_parser.add_argument("--passphrase-file", required=True, type=str)
    intermediate_parser.add_argument("--out-dir", default="./pki", type=str)
    intermediate_parser.add_argument("--validity-days", default=1825, type=int)
    intermediate_parser.add_argument("--pathlen", default=0, type=int)
    intermediate_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    intermediate_parser.add_argument("--log-file", default=None, type=str)

    cert_parser = ca_subparsers.add_parser("issue-cert")
    cert_parser.add_argument("--ca-cert", required=True, type=str)
    cert_parser.add_argument("--ca-key", required=True, type=str)
    cert_parser.add_argument("--ca-pass-file", required=True, type=str)
    cert_parser.add_argument("--template", choices=["server", "client", "code_signing"], required=True)
    cert_parser.add_argument("--subject", required=True, type=str)
    cert_parser.add_argument("--san", action="append")
    cert_parser.add_argument("--out-dir", default="./pki/certs", type=str)
    cert_parser.add_argument("--validity-days", default=365, type=int)
    cert_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    cert_parser.add_argument("--log-file", default=None, type=str)
    cert_parser.add_argument("--csr", default=None, type=str, help="CSR file to use instead of generating new key")

    ocsp_cert_parser = ca_subparsers.add_parser("issue-ocsp-cert")
    ocsp_cert_parser.add_argument("--ca-cert", required=True, type=str)
    ocsp_cert_parser.add_argument("--ca-key", required=True, type=str)
    ocsp_cert_parser.add_argument("--ca-pass-file", required=True, type=str)
    ocsp_cert_parser.add_argument("--subject", required=True, type=str)
    ocsp_cert_parser.add_argument("--san", action="append")
    ocsp_cert_parser.add_argument("--out-dir", default="./pki/certs", type=str)
    ocsp_cert_parser.add_argument("--validity-days", default=365, type=int)
    ocsp_cert_parser.add_argument("--key-type", choices=["rsa"], default="rsa")
    ocsp_cert_parser.add_argument("--key-size", type=int, default=2048)
    ocsp_cert_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    ocsp_cert_parser.add_argument("--log-file", default=None, type=str)

    show_parser = ca_subparsers.add_parser("show-cert")
    show_parser.add_argument("serial", type=str)
    show_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    show_parser.add_argument("--log-file", default=None, type=str)

    list_parser = ca_subparsers.add_parser("list-certs")
    list_parser.add_argument("--status", default=None, type=str)
    list_parser.add_argument("--format", default="table", type=str)
    list_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    list_parser.add_argument("--log-file", default=None, type=str)

    revoke_parser = ca_subparsers.add_parser("revoke")
    revoke_parser.add_argument("serial", type=str)
    revoke_parser.add_argument("--reason", default="unspecified", type=str)
    revoke_parser.add_argument("--force", action="store_true")
    revoke_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    revoke_parser.add_argument("--log-file", default=None, type=str)

    gen_crl_parser = ca_subparsers.add_parser("gen-crl")
    gen_crl_parser.add_argument("--ca", required=True, type=str)
    gen_crl_parser.add_argument("--next-update", default=7, type=int)
    gen_crl_parser.add_argument("--out-dir", default="./pki", type=str)
    gen_crl_parser.add_argument("--out-file", default=None, type=str)
    gen_crl_parser.add_argument("--passphrase-file", required=True, type=str)
    gen_crl_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    gen_crl_parser.add_argument("--log-file", default=None, type=str)

    # НОВЫЕ КОМАНДЫ ДЛЯ SPRINT 7
    audit_query_parser = ca_subparsers.add_parser("audit-query")
    audit_query_parser.add_argument("--from", dest="from_time", default=None, type=str)
    audit_query_parser.add_argument("--to", dest="to_time", default=None, type=str)
    audit_query_parser.add_argument("--level", default=None, type=str, choices=["INFO", "WARNING", "ERROR", "AUDIT"])
    audit_query_parser.add_argument("--operation", default=None, type=str)
    audit_query_parser.add_argument("--serial", default=None, type=str)
    audit_query_parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    audit_query_parser.add_argument("--verify", action="store_true")
    audit_query_parser.add_argument("--log-file", default="./pki/audit/audit.log", type=str)
    audit_query_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)

    audit_verify_parser = ca_subparsers.add_parser("audit-verify")
    audit_verify_parser.add_argument("--log-file", default="./pki/audit/audit.log", type=str)
    audit_verify_parser.add_argument("--chain-file", default="./pki/audit/chain.dat", type=str)
    audit_verify_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)

    compromise_parser = ca_subparsers.add_parser("compromise")
    compromise_parser.add_argument("--cert", required=True, type=str)
    compromise_parser.add_argument("--reason", default="keyCompromise", type=str)
    compromise_parser.add_argument("--force", action="store_true")
    compromise_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    compromise_parser.add_argument("--log-file", default=None, type=str)

    ct_verify_parser = ca_subparsers.add_parser("ct-verify")
    ct_verify_parser.add_argument("--serial", required=True, type=str)
    ct_verify_parser.add_argument("--ct-log", default="./pki/audit/ct.log", type=str)
    ct_verify_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)

    # client commands
    client_parser = subparsers.add_parser("client")
    client_subparsers = client_parser.add_subparsers(dest="client_command")

    gen_csr_parser = client_subparsers.add_parser("gen-csr")
    gen_csr_parser.add_argument("--subject", required=True, type=str)
    gen_csr_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    gen_csr_parser.add_argument("--key-size", type=int, default=2048)
    gen_csr_parser.add_argument("--san", action="append")
    gen_csr_parser.add_argument("--out-key", default="./key.pem", type=str)
    gen_csr_parser.add_argument("--out-csr", default="./request.csr.pem", type=str)
    gen_csr_parser.add_argument("--log-file", default=None, type=str)

    request_parser = client_subparsers.add_parser("request-cert")
    request_parser.add_argument("--csr", required=True, type=str)
    request_parser.add_argument("--template", choices=["server", "client", "code_signing"], required=True)
    request_parser.add_argument("--ca-url", required=True, type=str)
    request_parser.add_argument("--out-cert", default="./cert.pem", type=str)
    request_parser.add_argument("--api-key", default=None, type=str)
    request_parser.add_argument("--log-file", default=None, type=str)

    validate_parser = client_subparsers.add_parser("validate")
    validate_parser.add_argument("--cert", required=True, type=str)
    validate_parser.add_argument("--untrusted", action="append", default=[])
    validate_parser.add_argument("--trusted", action="append", default=["./pki/certs/ca.cert.pem"])
    validate_parser.add_argument("--validation-time", default=None, type=str)
    validate_parser.add_argument("--eku", choices=["server", "client", "code_signing"], default=None)
    validate_parser.add_argument("--format", choices=["table", "json"], default="table")
    validate_parser.add_argument("--log-file", default=None, type=str)

    check_parser = client_subparsers.add_parser("check-status")
    check_parser.add_argument("--cert", required=True, type=str)
    check_parser.add_argument("--ca-cert", required=True, type=str)
    check_parser.add_argument("--crl", default=None, type=str)
    check_parser.add_argument("--ocsp-url", default=None, type=str)
    check_parser.add_argument("--prefer-ocsp", action="store_true", default=True)
    check_parser.add_argument("--log-file", default=None, type=str)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    logger = setup_logger(getattr(args, "log_file", None))

    # Инициализация аудит логгера
    audit_dir = Path("./pki/audit")
    init_audit_logger(audit_dir, logger)

    try:
        validate_args(args)

        if args.command == "db" and args.db_command == "init":
            init_database(args.db_path)
            logger.info(f"Database initialised successfully at {Path(args.db_path).resolve()}")
            print("Database initialized successfully.")
            return

        if args.command == "repo" and args.repo_command == "serve":
            serve_repository(
                host=args.host,
                port=args.port,
                db_path=args.db_path,
                cert_dir=args.cert_dir,
                logger=logger,
                rate_limit=getattr(args, 'rate_limit', 0),
                rate_burst=getattr(args, 'rate_burst', 10),
            )
            return

        if args.command == "ocsp" and args.ocsp_command == "serve":
            serve_ocsp(
                host=args.host,
                port=args.port,
                db_path=args.db_path,
                responder_cert=args.responder_cert,
                responder_key=args.responder_key,
                ca_cert=args.ca_cert,
                cache_ttl=args.cache_ttl,
                logger=logger,
            )
            return

        # ==================== CA COMMANDS ====================
        if args.command == "ca":
            if args.ca_command == "init":
                init_root_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    logger=logger,
                    db_path=args.db_path,
                )
                print("Root CA initialized successfully.")
                return

            elif args.ca_command == "issue-intermediate":
                issue_intermediate_ca(
                    root_cert_path=args.root_cert,
                    root_key_path=args.root_key,
                    root_pass_file=args.root_pass_file,
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen,
                    logger=logger,
                    db_path=args.db_path,
                )
                print("Intermediate CA issued successfully.")
                return

            elif args.ca_command == "issue-cert":
                issue_end_entity_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file,
                    template=args.template,
                    subject=args.subject,
                    san_entries=args.san,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    logger=logger,
                    db_path=args.db_path,
                    csr_path=args.csr,
                )
                print("End-entity certificate issued successfully.")
                return

            elif args.ca_command == "issue-ocsp-cert":
                issue_ocsp_responder_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file,
                    subject=args.subject,
                    san_entries=args.san,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    logger=logger,
                    db_path=args.db_path,
                )
                print("OCSP responder certificate issued successfully.")
                return

            elif args.ca_command == "show-cert":
                pem = show_certificate_from_db(args.db_path, args.serial, logger)
                print(pem)
                return

            elif args.ca_command == "list-certs":
                output = list_certificates_from_db(args.db_path, logger, args.status, args.format)
                print(output)
                return

            elif args.ca_command == "revoke":
                revoke_certificate_via_cli(args.db_path, args.serial, args.reason, logger)
                print(f"Certificate {args.serial} revoked successfully.")
                return

            elif args.ca_command == "gen-crl":
                generate_crl_via_cli(
                    db_path=args.db_path,
                    out_dir=args.out_dir,
                    ca=args.ca,
                    passphrase_file=args.passphrase_file,
                    next_update_days=args.next_update,
                    logger=logger,
                    out_file=args.out_file,
                )
                print("CRL generated successfully.")
                return

            # НОВЫЕ КОМАНДЫ SPRINT 7
            elif args.ca_command == "audit-query":
                audit_logger = get_audit_logger()
                entries = audit_logger.query_logs(
                    from_time=getattr(args, 'from_time', None),
                    to_time=getattr(args, 'to_time', None),
                    level=args.level,
                    operation=args.operation,
                    serial=args.serial
                )

                if args.format == "json":
                    print(json.dumps(entries, indent=2, ensure_ascii=False))
                elif args.format == "csv":
                    import csv
                    if entries:
                        writer = csv.DictWriter(sys.stdout, fieldnames=entries[0].keys())
                        writer.writeheader()
                        writer.writerows(entries)
                else:
                    print(f"\n{'=' * 80}")
                    print("AUDIT LOG QUERY RESULTS")
                    print(f"{'=' * 80}")
                    if not entries:
                        print("No entries found matching the criteria.")
                    for entry in entries:
                        print(f"[{entry['timestamp']}] {entry['level']}")
                        print(f"  Operation: {entry['operation']} ({entry['status']})")
                        print(f"  Message: {entry['message']}")
                        if entry.get('metadata'):
                            print(f"  Metadata: {entry['metadata']}")
                        print()

                if args.verify:
                    is_valid, line, error = audit_logger.verify_integrity()
                    if is_valid:
                        print("✅ Audit log integrity verified")
                    else:
                        print(f"❌ Audit log tampered! {error}")
                        sys.exit(1)
                return

            elif args.ca_command == "audit-verify":
                audit_logger = get_audit_logger()
                is_valid, line, error = audit_logger.verify_integrity()
                if is_valid:
                    print("✅ Audit log integrity verified")
                else:
                    print(f"❌ Audit log integrity check FAILED!")
                    print(f"   Error: {error}")
                    sys.exit(1)
                return

            elif args.ca_command == "compromise":
                print(f"⚠️  SIMULATING PRIVATE KEY COMPROMISE")
                print(f"   Certificate: {args.cert}")
                print(f"   Reason: {args.reason}")

                if not args.force:
                    confirm = input("Are you sure you want to mark this key as compromised? (yes/no): ")
                    if confirm.lower() != "yes":
                        print("Aborted.")
                        return

                from cryptography import x509
                with open(args.cert, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                serial_hex = f"{cert.serial_number:x}".upper()

                revoke_certificate_via_cli(args.db_path, serial_hex, args.reason, logger)
                mark_key_compromised(args.db_path, args.cert, args.reason, logger)

                generate_crl_via_cli(
                    db_path=args.db_path,
                    out_dir="./pki",
                    ca="intermediate",
                    passphrase_file="./pki/passphrase.txt",
                    next_update_days=7,
                    logger=logger,
                )

                print(f"\n✅ Certificate {serial_hex} has been revoked due to key compromise")
                print(f"   The public key hash has been added to the compromised keys database")
                print(f"   Any future CSR using this key will be rejected")
                return

            elif args.ca_command == "ct-verify":
                ct_log = CTLog(Path(args.ct_log).parent)
                found = ct_log.verify_inclusion(args.serial)
                if found:
                    print(f"✅ Certificate with serial {args.serial} found in CT log")
                else:
                    print(f"❌ Certificate with serial {args.serial} NOT found in CT log")
                    print(f"   Checked log: {args.ct_log}")
                    sys.exit(1)
                return

        # ==================== CLIENT COMMANDS ====================
        if args.command == "client":
            from micropki.client import generate_csr, request_certificate, validate_certificate, check_status

            if args.client_command == "gen-csr":
                generate_csr(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    san_entries=args.san,
                    out_key_path=args.out_key,
                    out_csr_path=args.out_csr,
                    logger=logger,
                )
                print(f"✅ CSR generated successfully")
                print(f"   Private key: {args.out_key}")
                print(f"   CSR: {args.out_csr}")
                return

            elif args.client_command == "request-cert":
                request_certificate(
                    csr_path=args.csr,
                    template=args.template,
                    ca_url=args.ca_url,
                    out_cert_path=args.out_cert,
                    api_key=args.api_key,
                    logger=logger,
                )
                return

            elif args.client_command == "validate":
                validate_certificate(
                    cert_path=args.cert,
                    untrusted_paths=args.untrusted,
                    trusted_paths=args.trusted,
                    validation_time=args.validation_time,
                    expected_eku=args.eku,
                    output_format=args.format,
                    logger=logger,
                )
                return

            elif args.client_command == "check-status":
                check_status(
                    cert_path=args.cert,
                    ca_cert_path=args.ca_cert,
                    crl_source=args.crl,
                    ocsp_url=args.ocsp_url,
                    prefer_ocsp=args.prefer_ocsp,
                    logger=logger,
                )
                return

        parser.print_help()
        sys.exit(1)

    except Exception as e:
        logger.error(str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()