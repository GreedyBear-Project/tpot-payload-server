"""Directory scanning and metadata extraction for honeypot payload files.

Scans mounted honeypot data directories for recently modified files and
extracts metadata (hashes, MIME types, source honeypot) without executing
any sample.
"""

import logging
from collections.abc import Generator
from pathlib import Path

import magic

from app.hasher import compute_hashes

logger = logging.getLogger(__name__)


def _get_mime_type(file_path: Path, mime: magic.Magic | None) -> str:
    """Helper to detect MIME type strictly with python-magic."""
    if mime:
        try:
            return mime.from_file(str(file_path))
        except magic.MagicException:
            logger.exception("MIME detection failed for %s", file_path)
            return "unknown"
    return "unknown"


def derive_source_honeypot(file_path: str, base_dir: str) -> str:
    """Derive the source honeypot name from a file's path.

    Given a file at ``/data/dionaea/binaries/sample.bin`` and a base dir
    of ``/data``, this returns ``"dionaea"``.

    Args:
        file_path: Absolute path to the payload file.
        base_dir: Root directory where honeypot volumes are mounted.

    Returns:
        The top-level honeypot directory name, or ``"unknown"`` if the
        path cannot be resolved.
    """
    try:
        relative = Path(file_path).relative_to(base_dir)
        parts = relative.parts
        # Expected shape: <honeypot>/<...>/<filename> (at least 2 parts)
        _min_depth = 2
        if len(parts) >= _min_depth:
            return parts[0]
    except ValueError:
        logger.warning("Cannot derive source honeypot: %s is not under %s", file_path, base_dir)
    return "unknown"


def _init_magic() -> magic.Magic | None:
    """Helper to initialize python-magic safely."""
    try:
        return magic.Magic(mime=True)
    except (ImportError, TypeError, magic.MagicException):
        logger.warning("python-magic initialization failed; MIME types will be 'unknown'")
        return None


def _scan_files(directory: Path | str) -> Generator[tuple[Path, float, int]]:
    """Helper to recursively scan a directory for files, handling OSErrors."""
    base_path = Path(directory)
    if not base_path.is_dir():
        logger.warning("Directory does not exist: %s", base_path)
        return

    for file_path in base_path.iterdir():
        if not file_path.is_file():
            continue
        try:
            stat_result = file_path.stat()
            yield file_path, stat_result.st_mtime, stat_result.st_size
        except OSError:
            logger.exception("Failed to process %s", file_path)


def _extract_metadata(
    file_path: Path,
    mtime: float,
    size: int,
    mime: magic.Magic | None,
) -> dict | None:
    """Helper to compute hashes and assemble base metadata."""
    hashes = compute_hashes(file_path)
    if not hashes:
        return None

    return {
        "file_path": str(file_path),
        "mime_type": _get_mime_type(file_path, mime),
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "mtime": mtime,
        "size": size,
    }


def scan_payloads_by_range(
    directory: Path | str,
    start_ts: float,
    end_ts: float,
    base_dir: str,
) -> Generator[dict]:
    """Scan a directory for files whose mtime falls within [start_ts, end_ts].

    This is the stateless, timestamp-range variant used by the API's
    ``/recent`` endpoint.  Unlike :func:`scan_payloads` (which uses a
    relative ``max_age_seconds``), this accepts absolute Unix timestamps
    so GreedyBear can request precisely the extraction window it needs.

    Args:
        directory: Directory to scan recursively.
        start_ts: Start of the time window (Unix timestamp, inclusive).
        end_ts: End of the time window (Unix timestamp, inclusive).
        base_dir: Root mount point for deriving ``source_honeypot``.

    Yields:
        dict: Payload metadata including ``source_honeypot``.
    """
    mime = _init_magic()

    logger.info(
        "Scanning %s for payloads with mtime in [%s, %s]",
        directory,
        start_ts,
        end_ts,
    )

    for file_path, mtime, size in _scan_files(directory):
        if start_ts <= mtime <= end_ts:
            meta = _extract_metadata(file_path, mtime, size, mime)
            if meta:
                meta["source_honeypot"] = derive_source_honeypot(
                    str(file_path),
                    base_dir,
                )
                # Relative path from base_dir for deterministic download resolution.
                try:
                    meta["locator"] = str(Path(file_path).relative_to(base_dir))
                except ValueError:
                    meta["locator"] = file_path.name
                yield meta
