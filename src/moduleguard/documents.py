"""Canonical JSON document helpers."""

import json
from pathlib import Path
from typing import Any, Dict

from .errors import DocumentError

SCHEMA_VERSION = 1


def canonical_json(value: Dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON used for signing and verification."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def read_json_object(path: Path) -> Dict[str, Any]:
    """Read a JSON object and convert common file errors to DocumentError."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DocumentError("Cannot read {}: {}".format(path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise DocumentError("Invalid JSON in {}: {}".format(path, exc)) from exc
    if not isinstance(value, dict):
        raise DocumentError("{} must contain a JSON object".format(path))
    return value


def write_json_object(path: Path, value: Dict[str, Any]) -> None:
    """Write a stable, human-readable JSON object without overwriting files."""
    path = path.resolve()
    if path.exists():
        raise DocumentError("Refusing to overwrite existing file: {}".format(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise DocumentError("Cannot write {}: {}".format(path, exc)) from exc
