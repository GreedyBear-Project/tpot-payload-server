import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def compute_hashes(file_path: Path | str, chunk_size: int = 8192) -> dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes for a file in a single streaming pass.

    Args:
        file_path (Path | str): Path to the file to hash.
        chunk_size (int, optional): Size of the chunks to read. Defaults to 8192.

    Returns:
        dict[str, str]: A dictionary containing the ``md5``, ``sha1``, and
        ``sha256`` hashes on success. Returns an empty dictionary if the
        file cannot be opened or read due to an ``OSError``.
    """
    path = Path(file_path)
    logger.debug("Computing hashes for %s", path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError:
        logger.exception("Failed to compute hashes for %s", path)
        return {}

    result = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
    logger.debug("Hashes computed for %s: SHA256=%s", path, result["sha256"])
    return result
