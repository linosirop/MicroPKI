from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from micropki.ca import (
    init_root_ca,
    issue_intermediate_ca,
    issue_end_entity_certificate,
    show_certificate_from_db,
    list_certificates_from_db,
)
from micropki.logger import setup_logger
from micropki.certificates import parse_subject_dn
from micropki.database import init_database
from micropki.repository import serve_repository


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

    elif args.ca_command == "issue-cert":
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="micropki")
    subparsers = parser.add_subparsers(dest="command")

    db_parser = subparsers.add_parser("db")
    db_subparsers = db_parser.add_subparsers(dest="db_command")
    db_init_parser = db_subparsers.add_parser("init")
    db_init_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    db_init_parser.add_argument("--log-file", default=None, type=str)

    repo_parser = subparsers.add_parser("repo")
    repo_subparsers = repo_parser.add_subparsers(dest="repo_command")
    repo_serve_parser = repo_subparsers.add_parser("serve")
    repo_serve_parser.add_argument("--host", default="127.0.0.1", type=str)
    repo_serve_parser.add_argument("--port", default=8080, type=int)
    repo_serve_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    repo_serve_parser.add_argument("--cert-dir", default="./pki/certs", type=str)
    repo_serve_parser.add_argument("--log-file", default=None, type=str)

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
    intermediate_parser.add_argument("--key-type", choices=["rsa", "ecc"], required=True)
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

    show_parser = ca_subparsers.add_parser("show-cert")
    show_parser.add_argument("serial", type=str)
    show_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    show_parser.add_argument("--log-file", default=None, type=str)

    list_parser = ca_subparsers.add_parser("list-certs")
    list_parser.add_argument("--status", default=None, type=str)
    list_parser.add_argument("--format", default="table", type=str)
    list_parser.add_argument("--db-path", default=DEFAULT_DB_PATH, type=str)
    list_parser.add_argument("--log-file", default=None, type=str)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    logger = setup_logger(getattr(args, "log_file", None))

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
            )
            return

        if args.command == "ca" and args.ca_command == "init":
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

        if args.command == "ca" and args.ca_command == "issue-intermediate":
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

        if args.command == "ca" and args.ca_command == "issue-cert":
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
            )
            print("End-entity certificate issued successfully.")
            return

        if args.command == "ca" and args.ca_command == "show-cert":
            pem = show_certificate_from_db(args.db_path, args.serial, logger)
            print(pem, end="")
            return

        if args.command == "ca" and args.ca_command == "list-certs":
            output = list_certificates_from_db(
                db_path=args.db_path,
                logger=logger,
                status=args.status,
                output_format=args.format,
            )
            print(output)
            return

        parser.print_help()
        sys.exit(1)

    except Exception as e:
        logger.error(str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)