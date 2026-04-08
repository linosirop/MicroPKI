from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from micropki.ca import init_root_ca, issue_intermediate_ca, issue_end_entity_certificate
from micropki.logger import setup_logger
from micropki.certificates import parse_subject_dn


def validate_writable_directory(path_str: str) -> None:
    path = Path(path_str)
    parent_dir = path if path.exists() else path.parent
    if not parent_dir.exists():
        parent_dir = Path(".")
    if not os.access(parent_dir, os.W_OK):
        raise ValueError(f"Directory is not writable: {path_str}")


def validate_args(args: argparse.Namespace) -> None:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="micropki")
    subparsers = parser.add_subparsers(dest="command")

    ca_parser = subparsers.add_parser("ca")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command")

    init_parser = ca_subparsers.add_parser("init")
    init_parser.add_argument("--subject", required=True, type=str)
    init_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_parser.add_argument("--key-size", type=int, required=True)
    init_parser.add_argument("--passphrase-file", required=True, type=str)
    init_parser.add_argument("--out-dir", default="./pki", type=str)
    init_parser.add_argument("--validity-days", default=3650, type=int)
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
    cert_parser.add_argument("--log-file", default=None, type=str)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "ca" or not args.ca_command:
        parser.print_help()
        sys.exit(1)

    logger = setup_logger(getattr(args, "log_file", None))

    try:
        validate_args(args)

        if args.ca_command == "init":
            init_root_ca(
                subject=args.subject,
                key_type=args.key_type,
                key_size=args.key_size,
                passphrase_file=args.passphrase_file,
                out_dir=args.out_dir,
                validity_days=args.validity_days,
                logger=logger,
            )
            print("Root CA initialized successfully.")

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
            )
            print("Intermediate CA issued successfully.")

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
            )
            print("End-entity certificate issued successfully.")

    except Exception as e:
        logger.error(str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)