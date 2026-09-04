"""Ed25519 signing-key management."""

from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import DocumentError


def generate_key_pair(
    private_path: Path, public_path: Path, password: str
) -> Tuple[Path, Path]:
    """Generate an encrypted private key and a distributable public key."""
    private_path = private_path.resolve()
    public_path = public_path.resolve()
    if private_path == public_path:
        raise DocumentError("Private-key and public-key paths must be different")
    if private_path.exists() or public_path.exists():
        raise DocumentError("Refusing to overwrite an existing key file")
    if len(password) < 8:
        raise DocumentError("The private-key passphrase must contain at least 8 characters")

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)
    except OSError as exc:
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise DocumentError("Cannot write signing keys: {}".format(exc)) from exc
    return private_path, public_path


def load_private_key(path: Path, password: str) -> Ed25519PrivateKey:
    """Load an encrypted Ed25519 private key."""
    try:
        value = serialization.load_pem_private_key(
            path.read_bytes(), password=password.encode("utf-8")
        )
    except (OSError, TypeError, ValueError) as exc:
        raise DocumentError(
            "Cannot load private key {}; check the file and passphrase".format(path)
        ) from exc
    if not isinstance(value, Ed25519PrivateKey):
        raise DocumentError("{} is not an Ed25519 private key".format(path))
    return value


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key."""
    try:
        value = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise DocumentError("Cannot load public key {}".format(path)) from exc
    if not isinstance(value, Ed25519PublicKey):
        raise DocumentError("{} is not an Ed25519 public key".format(path))
    return value
