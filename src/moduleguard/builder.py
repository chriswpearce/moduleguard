"""No-admin native-extension build orchestration using Nuitka and Zig."""

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from importlib.util import find_spec
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from .crypto import load_public_key
from .errors import DocumentError
from .errors import ProtectionError
from .transform import create_protected_source, validate_module_name


def _run(command: Sequence[str], cwd: Path, environment: dict = None) -> str:
    result = subprocess.run(
        list(command),
        cwd=str(cwd),
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise ProtectionError(
            "Native build failed (exit {}):\n{}".format(result.returncode, result.stdout)
        )
    return result.stdout


def _distribution_name(module_name: str) -> str:
    return "moduleguard-protected-" + module_name.replace("_", "-").lower()


def _wheel_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", value)


def _wheel_tag() -> str:
    cache_tag = getattr(sys.implementation, "cache_tag", "")
    match = re.fullmatch(r"cpython-(\d+)", cache_tag)
    if not match:
        raise ProtectionError("Unsupported Python implementation tag: {}".format(cache_tag))
    interpreter = "cp" + match.group(1)
    platform = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return "{}-{}-{}".format(interpreter, interpreter, platform)


def _hash_record(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def _metadata_text(
    distribution_name: str, product_version: str, dependencies: Sequence[str]
) -> str:
    lines = [
        "Metadata-Version: 2.1",
        "Name: {}".format(distribution_name),
        "Version: {}".format(product_version),
        "Summary: ModuleGuard protected native module",
        "Requires-Python: >=3.9",
    ]
    lines.extend("Requires-Dist: {}".format(dependency) for dependency in dependencies)
    return "\n".join(lines) + "\n"


def _build_wheel(
    extension_path: Path,
    output_dir: Path,
    module_name: str,
    product_version: str,
    dependencies: Sequence[str],
) -> Path:
    distribution_name = _distribution_name(module_name)
    try:
        normalized_version = str(Version(product_version))
    except InvalidVersion as exc:
        raise ProtectionError("Invalid product version: {}".format(product_version)) from exc

    for dependency in dependencies:
        try:
            Requirement(dependency)
        except InvalidRequirement as exc:
            raise ProtectionError("Invalid runtime dependency: {}".format(dependency)) from exc

    wheel_distribution = _wheel_component(distribution_name)
    wheel_version = _wheel_component(normalized_version)
    tag = _wheel_tag()
    wheel_path = output_dir / "{}-{}-{}.whl".format(
        wheel_distribution, wheel_version, tag
    )
    dist_info = "{}-{}.dist-info".format(wheel_distribution, wheel_version)
    metadata = _metadata_text(distribution_name, normalized_version, dependencies).encode(
        "utf-8"
    )
    wheel_metadata = (
        "Wheel-Version: 1.0\n"
        "Generator: ModuleGuard\n"
        "Root-Is-Purelib: false\n"
        "Tag: {}\n".format(tag)
    ).encode("utf-8")
    extension_data = extension_path.read_bytes()
    members: List[Tuple[str, bytes]] = [
        (extension_path.name, extension_data),
        (dist_info + "/METADATA", metadata),
        (dist_info + "/WHEEL", wheel_metadata),
    ]
    record_name = dist_info + "/RECORD"
    record_buffer = io.StringIO(newline="")
    writer = csv.writer(record_buffer, lineterminator="\n")
    for name, data in members:
        writer.writerow((name, _hash_record(data), len(data)))
    writer.writerow((record_name, "", ""))
    members.append((record_name, record_buffer.getvalue().encode("utf-8")))

    with zipfile.ZipFile(str(wheel_path), "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return wheel_path


def _zig_environment() -> dict:
    environment = os.environ.copy()
    spec = find_spec("ziglang")
    if spec is None or spec.origin is None:
        raise ProtectionError(
            "The ziglang Python package is required. Install ModuleGuard's build dependencies."
        )
    zig_name = "zig.exe" if os.name == "nt" else "zig"
    zig_path = Path(spec.origin).resolve().parent / zig_name
    if not zig_path.is_file():
        raise ProtectionError("Cannot locate the ziglang compiler: {}".format(zig_path))
    environment["PATH"] = str(zig_path.parent) + os.pathsep + environment.get("PATH", "")
    return environment


def protect_module(
    source_path: Path,
    module_name: str,
    product_id: str,
    product_version: str,
    public_key_path: Path,
    output_dir: Path,
    dependencies: Iterable[str] = (),
) -> List[Path]:
    """Build an exact-name licensed `.pyd` and wheel in a clean output directory."""
    source_path = source_path.resolve()
    public_key_path = public_key_path.resolve()
    output_dir = output_dir.resolve()
    module_name = validate_module_name(module_name)
    if not source_path.is_file():
        raise ProtectionError("Target source does not exist: {}".format(source_path))
    if source_path.suffix.lower() != ".py":
        raise ProtectionError("Target source must be a .py file")
    if output_dir == source_path.parent:
        raise ProtectionError("Output must be a dedicated directory, not the source directory")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ProtectionError("Output directory must be empty: {}".format(output_dir))
    try:
        public_key_pem = public_key_path.read_bytes()
    except OSError as exc:
        raise ProtectionError("Cannot read public key {}: {}".format(public_key_path, exc)) from exc
    try:
        load_public_key(public_key_path)
    except DocumentError as exc:
        raise ProtectionError(str(exc)) from exc

    transformed = create_protected_source(
        source_path,
        module_name,
        product_id,
        product_version,
        public_key_pem,
    )
    runtime_dependencies = ["cryptography>=41"]
    for dependency in dependencies:
        dependency = dependency.strip()
        if dependency and dependency not in runtime_dependencies:
            runtime_dependencies.append(dependency)

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="moduleguard-build-") as temporary:
            build_dir = Path(temporary)
            protected_source = build_dir / (module_name + ".py")
            with protected_source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(transformed)

            command = [
                sys.executable,
                "-m",
                "nuitka",
                "--mode=module",
                "--zig",
                "--assume-yes-for-downloads",
                "--deployment",
                "--python-flag=no_docstrings",
                "--remove-output",
                "--no-pyi-file",
                "--output-dir={}".format(build_dir),
                str(protected_source),
            ]
            _run(command, build_dir, _zig_environment())

            extensions = list(build_dir.glob(module_name + "*.pyd"))
            if len(extensions) != 1:
                raise ProtectionError(
                    "Build produced {} native modules; expected one".format(len(extensions))
                )
            extension_path = output_dir / extensions[0].name
            shutil.copy2(str(extensions[0]), str(extension_path))
            wheel_path = _build_wheel(
                extension_path,
                output_dir,
                module_name,
                product_version,
                runtime_dependencies,
            )
            artifacts = [extension_path, wheel_path]

            manifest = {
                "schema_version": 1,
                "module_name": module_name,
                "product_id": product_id,
                "product_version": product_version,
                "python": "{}.{}.{}".format(*sys.version_info[:3]),
                "build_backend": "nuitka-zig",
                "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "artifacts": {
                    artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest()
                    for artifact in artifacts
                },
            }
            manifest_path = output_dir / "moduleguard-release.json"
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            artifacts.append(manifest_path)
            return artifacts
    except Exception:
        if output_dir.exists():
            shutil.rmtree(str(output_dir), ignore_errors=True)
        raise
