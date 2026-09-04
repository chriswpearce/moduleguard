"""Command-line interface for ModuleGuard."""

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .builder import protect_module
from .crypto import generate_key_pair, load_private_key
from .duration import parse_utc
from .errors import ModuleGuardError
from .inspector import inspect_release, report_text
from .licensing import issue_license, write_issued_license
from .product import default_license_path


def _password(environment_name: str, confirm: bool = False) -> str:
    value = os.environ.get(environment_name)
    if value is not None:
        return value
    value = getpass.getpass("Private-key passphrase: ")
    if confirm:
        confirmation = getpass.getpass("Confirm passphrase: ")
        if value != confirmation:
            raise ModuleGuardError("Passphrases do not match")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moduleguard",
        description=(
            "Build exact-name native Python modules protected by signed, "
            "portable, time-limited licences."
        ),
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser(
        "keygen", help="create an encrypted Ed25519 signing key pair"
    )
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    keygen.add_argument(
        "--password-env",
        default="MODULEGUARD_KEY_PASSWORD",
        help="environment variable containing the passphrase (default: %(default)s)",
    )

    issue = subparsers.add_parser(
        "issue", help="issue a signed portable licence"
    )
    issue.add_argument("--product-id", required=True)
    issue.add_argument("--private-key", type=Path, required=True)
    issue.add_argument("--product-version", required=True)
    validity = issue.add_mutually_exclusive_group()
    validity.add_argument(
        "--duration",
        help="validity such as 7d, 1mo, 6mo, or 1y (default: 7d)",
    )
    validity.add_argument(
        "--expires-at",
        help="exact ISO-8601 expiry, for example 2027-09-03T12:00:00Z",
    )
    issue.add_argument("--output", type=Path, required=True)
    access_requirement = issue.add_mutually_exclusive_group()
    access_requirement.add_argument(
        "--required-url",
        help="optional HTTP(S) URL that must be reachable whenever the module loads",
    )
    access_requirement.add_argument(
        "--required-path",
        help="optional absolute file or folder path that must be accessible whenever the module loads",
    )
    issue.add_argument(
        "--ledger", type=Path, help="append non-secret issuance metadata to this JSONL file"
    )
    issue.add_argument(
        "--password-env",
        default="MODULEGUARD_KEY_PASSWORD",
        help="environment variable containing the passphrase (default: %(default)s)",
    )

    protect = subparsers.add_parser(
        "protect", help="compile a source module into an exact-name licensed native module"
    )
    protect.add_argument("--source", type=Path, required=True)
    protect.add_argument(
        "--module-name",
        help="import name (default: source filename without .py)",
    )
    protect.add_argument("--product-id", required=True)
    protect.add_argument("--product-version", required=True)
    protect.add_argument("--public-key", type=Path, required=True)
    protect.add_argument("--output-dir", type=Path, required=True)
    protect.add_argument(
        "--dependency",
        action="append",
        default=[],
        help="additional wheel runtime dependency; repeat as needed",
    )

    inspect_parser = subparsers.add_parser(
        "inspect", help="audit a protected release for forbidden source/build files"
    )
    inspect_parser.add_argument("--release-dir", type=Path, required=True)
    inspect_parser.add_argument(
        "--forbid-text",
        action="append",
        default=[],
        help="fail if UTF-8 text occurs in any release file; repeat as needed",
    )

    path_parser = subparsers.add_parser(
        "license-path", help="show the default local licence path for a product"
    )
    path_parser.add_argument("--product-id", required=True)
    return parser


def _execute(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        private_path, public_path = generate_key_pair(
            args.private_key,
            args.public_key,
            _password(args.password_env, confirm=True),
        )
        print("Private signing key: {}".format(private_path))
        print("Public verification key: {}".format(public_path))
        print("Keep the private key and its passphrase out of release folders and source control.")
        return 0

    if args.command == "issue":
        private_key = load_private_key(
            args.private_key, _password(args.password_env, confirm=False)
        )
        expires_at = parse_utc(args.expires_at) if args.expires_at else None
        document = issue_license(
            args.product_id,
            private_key,
            args.product_version,
            duration=args.duration or "7d",
            expires_at=expires_at,
            required_url=args.required_url,
            required_path=args.required_path,
        )
        write_issued_license(args.output, document, args.ledger)
        payload = document["payload"]
        print("Licence: {}".format(args.output.resolve()))
        print("Licence ID: {}".format(payload["license_id"]))
        print("Valid from: {}".format(payload["not_before"]))
        print("Expires at: {}".format(payload["expires_at"]))
        print("Required URL: {}".format(payload["required_url"] or "none"))
        print("Required path: {}".format(payload["required_path"] or "none"))
        return 0

    if args.command == "protect":
        module_name = args.module_name or args.source.stem
        artifacts = protect_module(
            args.source,
            module_name,
            args.product_id,
            args.product_version,
            args.public_key,
            args.output_dir,
            args.dependency,
        )
        print("Protected release created:")
        for artifact in artifacts:
            print("  {}".format(artifact))
        return 0

    if args.command == "inspect":
        report = inspect_release(args.release_dir, args.forbid_text)
        print(report_text(report))
        return 0

    if args.command == "license-path":
        print(default_license_path(args.product_id))
        return 0

    raise ModuleGuardError("Unknown command: {}".format(args.command))


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _execute(args)
    except ModuleGuardError as exc:
        print("moduleguard: error: {}".format(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("moduleguard: cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
