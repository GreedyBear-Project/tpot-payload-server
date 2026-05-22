import contextlib
import time
from collections.abc import Generator
from pathlib import Path

import magic

from app.hasher import compute_hashes


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
    except Exception:
        mime = None

    for file_path in base_path.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            stat_result = file_path.stat()
            mtime = stat_result.st_mtime

            if (current_time - mtime) <= max_age_seconds:
                mime_type = "unknown"
                if mime:
                    with contextlib.suppress(Exception):
                        mime_type = mime.from_file(str(file_path))

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
            continue
