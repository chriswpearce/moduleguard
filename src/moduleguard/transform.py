"""Create a temporary source module with an embedded licence gate."""

import ast
import base64
import keyword
from pathlib import Path

from .errors import ProtectionError
from .product import product_slug, validate_product_id
from .obfuscation import obfuscate_source

_RUNTIME_TEMPLATE = r'''
# ModuleGuard runtime gate. This block is compiled into the native extension.
def __moduleguard_fail(message):
    raise ImportError("ModuleGuard licence check failed: " + message)


def __moduleguard_canonical(value):
    return __moduleguard_json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def __moduleguard_parse_utc(value):
    if not isinstance(value, str):
        __moduleguard_fail("licence date/time is invalid")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = __moduleguard_datetime.datetime.fromisoformat(text)
    except (TypeError, ValueError):
        __moduleguard_fail("licence date/time is invalid")
    if result.tzinfo is None or result.utcoffset() is None:
        __moduleguard_fail("licence date/time has no UTC offset")
    return result.astimezone(__moduleguard_datetime.timezone.utc).replace(microsecond=0)


def __moduleguard_central_path():
    __moduleguard_local = __moduleguard_os.environ.get("LOCALAPPDATA")
    if __moduleguard_local:
        return __moduleguard_pathlib.Path(__moduleguard_local) / "ModuleGuard" / "licenses" / __MODULEGUARD_LICENSE_FILENAME
    return None


def __moduleguard_adjacent_path():
    __moduleguard_location = None
    __moduleguard_compiled = globals().get("__compiled__")
    if __moduleguard_compiled is not None:
        __moduleguard_location = getattr(
            __moduleguard_compiled, "extension_filename", None
        )
    if not __moduleguard_location:
        __moduleguard_spec = globals().get("__spec__")
        if __moduleguard_spec is not None:
            __moduleguard_location = getattr(__moduleguard_spec, "origin", None)
    if not __moduleguard_location:
        __moduleguard_location = globals().get("__file__")
    if isinstance(__moduleguard_location, str) and __moduleguard_location:
        return __moduleguard_pathlib.Path(__moduleguard_location).resolve().parent / __MODULEGUARD_LICENSE_FILENAME
    return None


def __moduleguard_find_path():
    __moduleguard_override = __moduleguard_os.environ.get("MODULEGUARD_LICENSE_FILE")
    if __moduleguard_override:
        return __moduleguard_pathlib.Path(__moduleguard_override).expanduser()
    __moduleguard_candidates = (
        __moduleguard_adjacent_path(),
        __moduleguard_central_path(),
    )
    for __moduleguard_candidate in __moduleguard_candidates:
        if __moduleguard_candidate is not None and __moduleguard_candidate.is_file():
            return __moduleguard_candidate
    __moduleguard_searched = [
        str(__moduleguard_candidate)
        for __moduleguard_candidate in __moduleguard_candidates
        if __moduleguard_candidate is not None
    ]
    if __moduleguard_searched:
        __moduleguard_fail(
            "licence file not found; searched: {}".format(
                "; ".join(__moduleguard_searched)
            )
        )
    __moduleguard_fail(
        "licence file location is unavailable; set MODULEGUARD_LICENSE_FILE"
    )


def __moduleguard_check_url(__moduleguard_url):
    if __moduleguard_url is None:
        return
    if not isinstance(__moduleguard_url, str) or not __moduleguard_url:
        __moduleguard_fail("licence contains an invalid required URL")
    try:
        __moduleguard_request = __moduleguard_urllib_request.Request(
            __moduleguard_url,
            headers={"User-Agent": "ModuleGuard/0.3"},
        )
        with __moduleguard_urllib_request.urlopen(
            __moduleguard_request, timeout=5
        ) as __moduleguard_response:
            __moduleguard_status = getattr(__moduleguard_response, "status", None)
            if __moduleguard_status is None:
                __moduleguard_status = __moduleguard_response.getcode()
            if not isinstance(__moduleguard_status, int) or not 200 <= __moduleguard_status < 400:
                __moduleguard_fail(
                    "required website returned HTTP status {}: {}".format(
                        __moduleguard_status, __moduleguard_url
                    )
                )
            __moduleguard_response.read(1)
    except ImportError:
        raise
    except Exception as __moduleguard_error:
        __moduleguard_fail(
            "required website could not be loaded: {} ({})".format(
                __moduleguard_url, __moduleguard_error
            )
        )


def __moduleguard_check_path(__moduleguard_path_text):
    if __moduleguard_path_text is None:
        return
    if not isinstance(__moduleguard_path_text, str) or not __moduleguard_path_text:
        __moduleguard_fail("licence contains an invalid required path")
    __moduleguard_required_path = __moduleguard_pathlib.Path(
        __moduleguard_path_text
    )
    try:
        if __moduleguard_required_path.is_file():
            with __moduleguard_required_path.open("rb") as __moduleguard_file:
                __moduleguard_file.read(1)
            return
        if __moduleguard_required_path.is_dir():
            with __moduleguard_os.scandir(
                str(__moduleguard_required_path)
            ) as __moduleguard_entries:
                next(__moduleguard_entries, None)
            return
        __moduleguard_fail(
            "required path is not an accessible file or folder: {}".format(
                __moduleguard_path_text
            )
        )
    except ImportError:
        raise
    except Exception as __moduleguard_error:
        __moduleguard_fail(
            "required path could not be opened: {} ({})".format(
                __moduleguard_path_text, __moduleguard_error
            )
        )


def __moduleguard_check():
    __moduleguard_path = __moduleguard_find_path()
    try:
        __moduleguard_document = __moduleguard_json.loads(
            __moduleguard_path.read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        __moduleguard_fail("licence file not found: {}".format(__moduleguard_path))
    except (OSError, ValueError) as __moduleguard_error:
        __moduleguard_fail(
            "cannot read licence {}: {}".format(__moduleguard_path, __moduleguard_error)
        )
    if not isinstance(__moduleguard_document, dict):
        __moduleguard_fail("licence document must be a JSON object")
    __moduleguard_payload = __moduleguard_document.get("payload")
    __moduleguard_signature_text = __moduleguard_document.get("signature")
    if not isinstance(__moduleguard_payload, dict) or not isinstance(
        __moduleguard_signature_text, str
    ):
        __moduleguard_fail("licence must contain payload and signature fields")
    try:
        __moduleguard_signature = __moduleguard_base64.b64decode(
            __moduleguard_signature_text, validate=True
        )
        __moduleguard_public_bytes = __moduleguard_base64.b64decode(
            __MODULEGUARD_PUBLIC_KEY_B64, validate=True
        )
        __moduleguard_public_key = __moduleguard_serialization.load_pem_public_key(
            __moduleguard_public_bytes
        )
        __moduleguard_public_key.verify(
            __moduleguard_signature, __moduleguard_canonical(__moduleguard_payload)
        )
    except Exception as __moduleguard_error:
        __moduleguard_fail("licence signature is invalid")
    if __moduleguard_payload.get("document_type") != "moduleguard-license":
        __moduleguard_fail("document is not a ModuleGuard licence")
    if __moduleguard_payload.get("schema_version") != 3:
        __moduleguard_fail(
            "licence schema version is unsupported; issue a new portable licence"
        )
    if __moduleguard_payload.get("licence_scope") != "portable":
        __moduleguard_fail("licence is not portable")
    if (
        __moduleguard_payload.get("required_url") is not None
        and __moduleguard_payload.get("required_path") is not None
    ):
        __moduleguard_fail("licence cannot require both a URL and a path")
    if __moduleguard_payload.get("product_id") != __MODULEGUARD_PRODUCT_ID:
        __moduleguard_fail("licence is for a different product")
    if __moduleguard_payload.get("product_version") != __MODULEGUARD_PRODUCT_VERSION:
        __moduleguard_fail(
            "licence is for product version {}, not {}".format(
                __moduleguard_payload.get("product_version"),
                __MODULEGUARD_PRODUCT_VERSION,
            )
        )
    __moduleguard_issued = __moduleguard_parse_utc(
        __moduleguard_payload.get("issued_at")
    )
    __moduleguard_start = __moduleguard_parse_utc(
        __moduleguard_payload.get("not_before")
    )
    __moduleguard_end = __moduleguard_parse_utc(
        __moduleguard_payload.get("expires_at")
    )
    if __moduleguard_end <= __moduleguard_start or __moduleguard_start < __moduleguard_issued:
        __moduleguard_fail("licence validity dates are inconsistent")
    __moduleguard_now = __moduleguard_datetime.datetime.now(
        __moduleguard_datetime.timezone.utc
    ).replace(microsecond=0)
    if __moduleguard_now < __moduleguard_start:
        __moduleguard_fail("licence is not valid until {}".format(__moduleguard_payload.get("not_before")))
    if __moduleguard_now >= __moduleguard_end:
        __moduleguard_fail("licence expired at {}".format(__moduleguard_payload.get("expires_at")))
    __moduleguard_check_url(__moduleguard_payload.get("required_url"))
    __moduleguard_check_path(__moduleguard_payload.get("required_path"))


import base64 as __moduleguard_base64
import datetime as __moduleguard_datetime
import json as __moduleguard_json
import os as __moduleguard_os
import pathlib as __moduleguard_pathlib
import urllib.request as __moduleguard_urllib_request
from cryptography.hazmat.primitives import serialization as __moduleguard_serialization

__MODULEGUARD_PRODUCT_ID = __MODULEGUARD_PRODUCT_ID_TOKEN__
__MODULEGUARD_PRODUCT_VERSION = __MODULEGUARD_PRODUCT_VERSION_TOKEN__
__MODULEGUARD_LICENSE_FILENAME = __MODULEGUARD_LICENSE_FILENAME_TOKEN__
__MODULEGUARD_PUBLIC_KEY_B64 = __MODULEGUARD_PUBLIC_KEY_B64_TOKEN__
__moduleguard_check()

del __moduleguard_check, __moduleguard_find_path, __moduleguard_adjacent_path
del __moduleguard_central_path, __moduleguard_check_url, __moduleguard_check_path
del __moduleguard_parse_utc, __moduleguard_canonical, __moduleguard_fail
del __moduleguard_base64, __moduleguard_datetime
del __moduleguard_json, __moduleguard_os, __moduleguard_pathlib
del __moduleguard_urllib_request
del __moduleguard_serialization, __MODULEGUARD_PRODUCT_ID
del __MODULEGUARD_PRODUCT_VERSION, __MODULEGUARD_LICENSE_FILENAME
del __MODULEGUARD_PUBLIC_KEY_B64
'''


def validate_module_name(module_name: str) -> str:
    """Require a top-level Python identifier for the exact-name extension."""
    if not module_name.isidentifier() or keyword.iskeyword(module_name):
        raise ProtectionError(
            "Module name {!r} must be one top-level Python identifier".format(module_name)
        )
    return module_name


def _insertion_line(tree: ast.Module) -> int:
    index = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, (ast.Str, ast.Constant)) and isinstance(
            getattr(value, "s", getattr(value, "value", None)), str
        ):
            index = 1
    while index < len(body):
        statement = body[index]
        if isinstance(statement, ast.ImportFrom) and statement.module == "__future__":
            index += 1
        else:
            break
    if index == 0:
        return 1
    return int(getattr(body[index - 1], "end_lineno", body[index - 1].lineno)) + 1


def create_protected_source(
    source_path: Path,
    module_name: str,
    product_id: str,
    product_version: str,
    public_key_pem: bytes,
) -> str:
    """Return automatically obfuscated source containing a self-contained licence gate."""
    module_name = validate_module_name(module_name)
    product_id = validate_product_id(product_id)
    if not product_version.strip():
        raise ProtectionError("Product version must not be empty")
    try:
        source = source_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ProtectionError("Cannot read source {}: {}".format(source_path, exc)) from exc
    try:
        tree = ast.parse(source, filename=source_path.name)
        compile(tree, source_path.name, "exec")
    except SyntaxError as exc:
        raise ProtectionError("Target source has a syntax error: {}".format(exc)) from exc
    gate = _RUNTIME_TEMPLATE.strip()
    replacements = {
        "__MODULEGUARD_PRODUCT_ID_TOKEN__": repr(product_id),
        "__MODULEGUARD_PRODUCT_VERSION_TOKEN__": repr(product_version.strip()),
        "__MODULEGUARD_LICENSE_FILENAME_TOKEN__": repr(
            product_slug(product_id) + ".lic"
        ),
        "__MODULEGUARD_PUBLIC_KEY_B64_TOKEN__": repr(
            base64.b64encode(public_key_pem).decode("ascii")
        ),
    }
    for token, value in replacements.items():
        gate = gate.replace(token, value)
    lines = source.splitlines(keepends=True)
    insertion = _insertion_line(tree) - 1
    lines.insert(insertion, "\n" + gate + "\n\n")
    transformed = "".join(lines)
    try:
        compile(transformed, module_name + ".py", "exec")
    except SyntaxError as exc:
        raise ProtectionError("Generated protected source is invalid: {}".format(exc)) from exc
    return obfuscate_source(transformed, module_name + ".py")
