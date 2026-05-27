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
