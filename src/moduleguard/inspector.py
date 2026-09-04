"""Audit ModuleGuard release directories and wheels."""

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .errors import ProtectionError

_FORBIDDEN_SUFFIXES = {
    ".py",
    ".pyc",
    ".pyx",
    ".pxd",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".pdb",
    ".obj",
    ".lib",
    ".exp",
    ".html",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inspect_wheel(path: Path) -> List[str]:
    violations = []
    try:
        with zipfile.ZipFile(str(path)) as archive:
            for member in archive.namelist():
                suffix = Path(member).suffix.lower()
                if suffix in _FORBIDDEN_SUFFIXES:
                    violations.append("{} contains forbidden member {}".format(path.name, member))
    except (OSError, zipfile.BadZipFile) as exc:
        violations.append("Cannot read wheel {}: {}".format(path.name, exc))
    return violations


def inspect_release(
    release_dir: Path, forbidden_text: Iterable[str] = ()
) -> Dict[str, Any]:
    """Inspect a release and raise if source/build material is present."""
    release_dir = release_dir.resolve()
    if not release_dir.is_dir():
        raise ProtectionError("Release directory does not exist: {}".format(release_dir))
    files = sorted(path for path in release_dir.rglob("*") if path.is_file())
    if not files:
        raise ProtectionError("Release directory is empty")
    violations: List[str] = []
    hashes: Dict[str, str] = {}
    wheels = 0
    extensions = 0
    forbidden_bytes: List[Tuple[str, bytes]] = [
        (text, text.encode("utf-8")) for text in forbidden_text if text
    ]
    for path in files:
        relative = path.relative_to(release_dir).as_posix()
        suffix = path.suffix.lower()
        hashes[relative] = _sha256(path)
        if suffix in _FORBIDDEN_SUFFIXES:
            violations.append("Forbidden release file: {}".format(relative))
        if suffix == ".whl":
            wheels += 1
            violations.extend(_inspect_wheel(path))
        if suffix == ".pyd":
            extensions += 1
        if forbidden_bytes:
            data = path.read_bytes()
            for text, marker in forbidden_bytes:
                if marker in data:
                    violations.append("{} contains forbidden text {!r}".format(relative, text))
    if wheels < 1:
        violations.append("Release contains no wheel")
    if extensions < 1:
        violations.append("Release contains no drop-in .pyd")
    report: Dict[str, Any] = {
        "release_directory": str(release_dir),
        "files": hashes,
        "wheel_count": wheels,
        "extension_count": extensions,
        "violations": violations,
        "passed": not violations,
    }
    if violations:
        raise ProtectionError(
            "Release inspection failed:\n- " + "\n- ".join(violations)
        )
    return report


def report_text(report: Dict[str, Any]) -> str:
    """Return a readable inspection report."""
    return json.dumps(report, sort_keys=True, indent=2)
