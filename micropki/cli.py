from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from micropki.ca import init_root_ca
from micropki.logger import setup_logger
from micropki.certificates import parse_subject_dn


def validate_args(args: argparse.Namespace) -> None:
    if not args.subject or not args.subject.strip():
        raise ValueError("--subject must be a non-empty string")

    parse_subject_dn(args.subject)

    if args.key_type not in ("rsa", "ecc"):
        raise ValueError("--key-type must be either 'rsa' or 'ecc'")

    if args.key_type == "rsa" and args.key_size != 4096:
        raise ValueError("For RSA, --key-size must be 4096")

    if args.key_type == "ecc" and args.key_size != 384:
        raise ValueError("For ECC, --key-size must be 384")

    pass_file = Path(args.passphrase_file)
    if not pass_file.exists() or not pass_file.is_file():
        raise ValueError("--passphrase-file must exist and be a readable file")

    if args.validity_days <= 0:
        raise ValueError("--validity-days must be a positive integer")

    out_dir = Path(args.out_dir)
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError("--out-dir exists but is not a directory")

    parent_dir = out_dir if out_dir.exists() else out_dir.parent
    if not parent_dir.exists():
        parent_dir = Path(".")

    if not os.access(parent_dir, os.W_OK):
        raise ValueError("--out-dir is not writable")


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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "ca" or args.ca_command != "init":
        parser.print_help()
        sys.exit(1)

    logger = setup_logger(args.log_file)

    try:
        validate_args(args)
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
    except Exception as e:
        logger.error(str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)