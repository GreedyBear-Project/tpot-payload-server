"""Directory scanning and metadata extraction for honeypot payload files.

Scans mounted honeypot data directories for recently modified files and
extracts metadata (hashes, MIME types, source honeypot) without executing
any sample.
"""

import logging
import time
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
        if parts:
            return parts[0]
    except ValueError:
        logger.warning("Cannot derive source honeypot: %s is not under %s", file_path, base_dir)
    return "unknown"


def scan_payloads(directory: Path | str, max_age_seconds: int) -> Generator[dict]:
    """Scan a directory recursively for files modified within the last max_age_seconds.

    Extracts metadata (hashes, MIME types) without executing the files.

    Args:
        directory (Path | str): The directory path to scan.
        max_age_seconds (int): The maximum age of the file in seconds to be included.

    Yields:
        dict: A dictionary containing file metadata like path, mime_type, hashes, etc.
    """
    current_time = time.time()
    base_path = Path(directory)

    try:
        mime = magic.Magic(mime=True)
    except (ImportError, TypeError, magic.MagicException):
        logger.warning("python-magic initialization failed; MIME types will be 'unknown'")
        mime = None

    logger.info("Scanning %s for payloads modified within %d seconds", base_path, max_age_seconds)

    for file_path in base_path.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            stat_result = file_path.stat()
            mtime = stat_result.st_mtime

            if (current_time - mtime) <= max_age_seconds:
                mime_type = _get_mime_type(file_path, mime)

                hashes = compute_hashes(file_path)
                if not hashes:
                    continue

                yield {
                    "file_path": str(file_path),
                    "mime_type": mime_type,
                    "md5": hashes.get("md5"),
                    "sha1": hashes.get("sha1"),
                    "sha256": hashes.get("sha256"),
                    "mtime": mtime,
                    "size": stat_result.st_size,
                }
        except OSError:
            logger.exception("Failed to process %s", file_path)
            continue


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
    base_path = Path(directory)

    if not base_path.is_dir():
        logger.warning("Directory does not exist: %s", base_path)
        return

    try:
        mime = magic.Magic(mime=True)
    except (ImportError, TypeError, magic.MagicException):
        logger.warning("python-magic initialization failed; MIME types will be 'unknown'")
        mime = None

    logger.info(
        "Scanning %s for payloads with mtime in [%s, %s]",
        base_path,
        start_ts,
        end_ts,
    )

    for file_path in base_path.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            stat_result = file_path.stat()
            mtime = stat_result.st_mtime

            if start_ts <= mtime <= end_ts:
                mime_type = _get_mime_type(file_path, mime)

                hashes = compute_hashes(file_path)
                if not hashes:
                    continue

                yield {
                    "file_path": str(file_path),
                    "mime_type": mime_type,
                    "md5": hashes.get("md5"),
                    "sha1": hashes.get("sha1"),
                    "sha256": hashes.get("sha256"),
                    "mtime": mtime,
                    "size": stat_result.st_size,
                    "source_honeypot": derive_source_honeypot(
                        str(file_path),
                        base_dir,
                    ),
                }
        except OSError:
            logger.exception("Failed to process %s", file_path)
            continue
