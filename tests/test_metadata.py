"""Tests for T-Pot Payload Server hash computation and metadata extraction."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import magic

from app.hasher import compute_hashes
from app.scanner import _get_mime_type


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


def test_compute_hashes_oserror() -> None:
    """Test that compute_hashes returns an empty dict when the file cannot be read."""
    hashes = compute_hashes(Path("/nonexistent/path/payload.bin"))

    assert hashes == {}


def test_get_mime_type_magic_exception() -> None:
    """Test that _get_mime_type returns 'unknown' when MagicException is raised."""
    mock_mime = magic.Magic(mime=True)

    with patch.object(mock_mime, "from_file", side_effect=magic.MagicException("corrupted")):
        result = _get_mime_type(Path("/some/file.bin"), mock_mime)

    assert result == "unknown"
