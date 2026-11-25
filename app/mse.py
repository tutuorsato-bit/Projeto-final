from __future__ import annotations

import json
import socket
import struct
import time
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from app.config import settings

MAX_ARCHIVE_ENTRIES = 20_000
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_YARA_ENTRIES = 10_000
MAX_YARA_ENTRY_BYTES = 10 * 1024 * 1024
MAX_YARA_TOTAL_BYTES = 128 * 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
BLOCKED_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".sh", ".com"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SAFE_PNG_CHUNKS = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}


def sanitize_png(data: bytes) -> bytes:
    if len(data) < 33 or len(data) > MAX_IMAGE_BYTES or not data.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid or oversized PNG image")
    output = bytearray(PNG_SIGNATURE)
    offset = len(PNG_SIGNATURE)
    chunk_count = 0
    saw_header = False
    saw_palette = False
    saw_image_data = False
    image_data_ended = False
    saw_end = False
    color_type: int | None = None
    while offset < len(data):
        chunk_count += 1
        if chunk_count > 4096 or offset + 12 > len(data):
            raise ValueError("PNG contains too many or incomplete chunks")
        length = struct.unpack_from("!I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("PNG chunk exceeds file bounds")
        chunk = data[offset + 4 : end - 4]
        expected_crc = struct.unpack_from("!I", data, end - 4)[0]
        if zlib.crc32(chunk) & 0xFFFFFFFF != expected_crc:
            raise ValueError("PNG chunk checksum is invalid")
        payload = data[offset + 8 : end - 4]
        if not saw_header:
            if kind != b"IHDR" or length != 13:
                raise ValueError("PNG must begin with a valid IHDR chunk")
            width, height = struct.unpack_from("!II", payload)
            bit_depth = payload[8]
            color_type = payload[9]
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width < 1
                or height < 1
                or width > 8192
                or height > 8192
                or width * height > MAX_IMAGE_PIXELS
                or color_type not in valid_depths
                or bit_depth not in valid_depths.get(color_type, set())
                or payload[10:] != b"\0\0\0"
            ):
                raise ValueError("PNG dimensions exceed the safe limits")
            saw_header = True
        elif kind == b"IHDR":
            raise ValueError("PNG contains multiple IHDR chunks")
        if kind == b"PLTE":
            if (
                saw_palette
                or saw_image_data
                or color_type in {0, 4}
                or not (3 <= length <= 768 and length % 3 == 0)
            ):
                raise ValueError("PNG palette chunk is invalid")
            saw_palette = True
        if kind == b"IDAT":
            if image_data_ended or not saw_header or (color_type == 3 and not saw_palette):
                raise ValueError("PNG image data chunks are out of order")
            saw_image_data = True
        elif saw_image_data and kind != b"IEND":
            image_data_ended = True
        if kind == b"IEND":
            if length != 0 or not saw_image_data:
                raise ValueError("PNG ending chunk is invalid")
            saw_end = True
            if end != len(data):
                raise ValueError("PNG has trailing data")
        if kind == b"tRNS":
            valid_transparency_length = (
                (color_type == 0 and length == 2)
                or (color_type == 2 and length == 6)
                or (color_type == 3 and saw_palette and 1 <= length <= 256)
            )
            if saw_image_data or not valid_transparency_length:
                raise ValueError("PNG transparency chunk is invalid")
        if kind not in SAFE_PNG_CHUNKS and kind[:1].isupper():
            raise ValueError("PNG contains an unknown critical chunk")
        if kind in SAFE_PNG_CHUNKS:
            output.extend(data[offset:end])
        offset = end
        if saw_end:
            break
    if not saw_end:
        raise ValueError("PNG is missing its ending chunk")
    return bytes(output)


def _inspect_png(path: Path) -> dict[str, object]:
    try:
        original = path.read_bytes()
        sanitized = sanitize_png(original)
    except (OSError, ValueError, struct.error) as exc:
        return {"status": "suspicious", "reason": f"invalid_png:{type(exc).__name__}"}
    if sanitized != original:
        return {"status": "suspicious", "reason": "png_metadata_not_sanitized"}
    return {"status": "clean", "format": "png"}


class ScanResult:
    def __init__(self, status: str, results: dict[str, object]):
        self.status = status
        self.results = results


def _clamav_scan(path: Path) -> dict[str, object]:
    with socket.create_connection((settings.clamd_host, settings.clamd_port), timeout=15) as sock:
        sock.settimeout(30)
        sock.sendall(b"zINSTREAM\0")
        with path.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                sock.sendall(struct.pack("!I", len(chunk)) + chunk)
        sock.sendall(struct.pack("!I", 0))
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            if len(response) + len(chunk) > 4096:
                raise RuntimeError("ClamAV response exceeded the protocol limit")
            response.extend(chunk)
            if b"\0" in chunk:
                break
        text = response.decode("utf-8", errors="replace").strip("\0\r\n ")
        if text == "stream: OK":
            return {"status": "clean", "engine": "clamav"}
        if text.startswith("stream: ") and text.endswith(" FOUND") and len(text) > len("stream:  FOUND"):
            return {"status": "threat", "engine": "clamav", "detail": text[:240]}
        if not text:
            raise RuntimeError("ClamAV closed the connection without a response")
        raise RuntimeError(f"ClamAV returned an invalid INSTREAM response: {text[:240]}")


def _yara_scan(path: Path, original_name: str) -> dict[str, object]:
    try:
        import yara
    except ImportError as exc:
        raise RuntimeError("YARA Python bindings are not installed") from exc
    if not settings.yara_rules_path.is_file():
        raise RuntimeError("YARA rules file is missing")
    try:
        rules = yara.compile(filepath=str(settings.yara_rules_path))
    except yara.Error as exc:
        raise RuntimeError("YARA rules could not be compiled") from exc
    if Path(original_name).suffix.lower() == ".png":
        try:
            matches = rules.match(str(path), timeout=20)
        except yara.Error as exc:
            raise RuntimeError("YARA image scan failed") from exc
        if matches:
            return {
                "status": "suspicious",
                "engine": "yara",
                "matches": [str(match)[:120] for match in matches[:20]],
            }
        return {"status": "clean", "engine": "yara"}
    matched_rules: set[str] = set()
    bytes_scanned = 0
    started = time.monotonic()
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [entry for entry in archive.infolist() if not entry.is_dir()]
            if len(entries) > MAX_YARA_ENTRIES:
                raise RuntimeError("Archive exceeds YARA entry scan limit")
            for entry in entries:
                if entry.file_size > MAX_YARA_ENTRY_BYTES:
                    raise RuntimeError("Archive contains an entry above the YARA scan size limit")
                bytes_scanned += entry.file_size
                if bytes_scanned > MAX_YARA_TOTAL_BYTES:
                    raise RuntimeError("Archive exceeds total YARA scan size limit")
                if time.monotonic() - started > 60:
                    raise RuntimeError("YARA scan exceeded the time limit")
                matches = rules.match(data=archive.read(entry), timeout=3)
                matched_rules.update(str(match)[:120] for match in matches)
    except (
        OSError,
        EOFError,
        RuntimeError,
        yara.Error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        raise RuntimeError(f"YARA archive inspection failed: {type(exc).__name__}") from exc
    if matched_rules:
        return {
            "status": "suspicious",
            "engine": "yara",
            "matches": sorted(matched_rules)[:20],
            "entries_scanned": len(entries),
        }
    return {"status": "clean", "engine": "yara", "entries_scanned": len(entries)}


def _inspect_archive(path: Path, original_name: str) -> dict[str, object]:
    if Path(original_name).suffix.lower() == ".png":
        return _inspect_png(path)
    if Path(original_name).suffix.lower() not in {".jar", ".zip", ".mcpack", ".mcaddon", ".mctemplate"}:
        return {"status": "suspicious", "reason": "unsupported_file_type"}
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries:
                return {"status": "suspicious", "reason": "empty_archive"}
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return {"status": "suspicious", "reason": "too_many_archive_entries"}
            total_size = 0
            suspicious_paths = []
            blocked_entries = []
            for entry in entries:
                normalized_name = entry.filename.replace("\\", "/")
                member_path = PurePosixPath(normalized_name)
                mode = (entry.external_attr >> 16) & 0xFFFF
                if (
                    "\0" in entry.filename
                    or member_path.is_absolute()
                    or ".." in member_path.parts
                    or (member_path.parts and ":" in member_path.parts[0])
                ):
                    suspicious_paths.append(normalized_name[:160])
                if (mode & 0o170000) == 0o120000:
                    suspicious_paths.append(normalized_name[:160])
                if Path(normalized_name).suffix.lower() in BLOCKED_SUFFIXES:
                    blocked_entries.append(normalized_name[:160])
                total_size += entry.file_size
                if total_size > MAX_UNCOMPRESSED_BYTES:
                    return {"status": "suspicious", "reason": "uncompressed_size_limit"}
                if entry.file_size and entry.compress_size == 0:
                    return {"status": "suspicious", "reason": "invalid_compression_metadata"}
                if entry.compress_size and entry.file_size / entry.compress_size > MAX_COMPRESSION_RATIO:
                    return {"status": "suspicious", "reason": "compression_ratio_limit"}
            if suspicious_paths:
                return {
                    "status": "suspicious",
                    "reason": "unsafe_archive_paths",
                    "entries": suspicious_paths[:20],
                }
            if blocked_entries:
                return {
                    "status": "suspicious",
                    "reason": "executable_or_script_entries",
                    "entries": blocked_entries[:20],
                }
            return {
                "status": "clean",
                "entries": len(entries),
                "uncompressed_bytes": total_size,
            }
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, zlib.error) as exc:
        return {"status": "suspicious", "reason": f"invalid_archive:{type(exc).__name__}"}


def _virustotal_scan(sha256: str) -> dict[str, object] | None:
    if not settings.virustotal_api_key:
        return None
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": settings.virustotal_api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "unknown", "engine": "virustotal", "reason": "hash_not_found"}
        raise RuntimeError(f"VirusTotal request failed with HTTP {exc.code}") from exc
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not isinstance(stats, dict):
        raise RuntimeError("VirusTotal response omitted analysis statistics")
    return {
        "status": (
            "threat"
            if int(stats.get("malicious", 0)) > 0
            else "suspicious"
            if int(stats.get("suspicious", 0)) > 0
            else "clean"
        ),
        "engine": "virustotal",
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "undetected": int(stats.get("undetected", 0)),
    }


def scan_file(path: Path, original_name: str, sha256: str) -> ScanResult:
    results: dict[str, object] = {"structure": _inspect_archive(path, original_name)}
    errors: dict[str, object] = {}
    for engine, scanner in (
        ("clamav", lambda: _clamav_scan(path)),
        ("yara", lambda: _yara_scan(path, original_name)),
    ):
        try:
            results[engine] = scanner()
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            errors[engine] = {"type": type(exc).__name__, "message": _safe_error_message(exc)}
    vt = None
    try:
        vt = _virustotal_scan(sha256)
        if vt is not None:
            results["virustotal"] = vt
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        errors["virustotal"] = {"type": type(exc).__name__, "message": _safe_error_message(exc)}
    if errors:
        results["scanner_errors"] = errors
    statuses = [
        value["status"]
        for value in results.values()
        if isinstance(value, dict) and isinstance(value.get("status"), str)
    ]
    if "threat" in statuses:
        return ScanResult("rejected", results)
    if "suspicious" in statuses:
        return ScanResult("suspicious", results)
    if errors or "unknown" in statuses:
        return ScanResult("inconclusive", results)
    return ScanResult("approved", results)


def _safe_error_message(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "Scanner request timed out"
    if isinstance(exc, OSError):
        return "Scanner service is unavailable"
    return str(exc)[:240]
