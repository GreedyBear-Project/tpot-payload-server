import os
import tempfile
import time
from pathlib import Path

from app.hasher import compute_hashes
from app.scanner import scan_payloads


def test_compute_hashes() -> None:
    """Test the hash computation for a sample payload file."""
    with tempfile.TemporaryDirectory() as td:
        file_path = Path(td) / "test_payload.txt"
        file_path.write_text("malicious payload test")

        hashes = compute_hashes(file_path)

        assert hashes.get("md5") is not None
        assert hashes.get("sha1") is not None
        assert hashes.get("sha256") is not None
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert len(hashes["sha256"]) == 64


def test_scan_payloads() -> None:
    """Test the scanner filters out old files and extracts metadata correctly."""
    with tempfile.TemporaryDirectory() as td:
        file_path1 = Path(td) / "recent_payload.txt"
        file_path2 = Path(td) / "old_payload.txt"

        file_path1.write_text("recent payload content")

        # Simulate an old file by changing its mtime to 1 hour ago
        file_path2.write_text("old payload content")
        old_time = time.time() - 3600
        os.utime(file_path2, (old_time, old_time))

        # Scan for payloads modified in the last 60 seconds
        results = list(scan_payloads(td, 60))

        # Should only find the recent payload
        assert len(results) == 1
        payload = results[0]

        assert payload["file_path"] == str(file_path1)
        assert "text" in payload["mime_type"] or "plain" in payload["mime_type"]
        assert payload["md5"] is not None
        assert payload["sha1"] is not None
        assert payload["sha256"] is not None
        assert payload["size"] > 0
        assert payload["mtime"] > old_time
