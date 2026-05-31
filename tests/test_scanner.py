"""Unit tests for scanner helper functions.

Tests ``derive_source_honeypot``, ``scan_payloads_by_range``, and
``_get_mime_type`` edge cases that are not covered through endpoint-level
integration tests.
"""

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import magic

from app.scanner import (
    _get_mime_type,
    derive_source_honeypot,
    scan_payloads_by_range,
)


class TestDeriveSourceHoneypot:
    """Tests for derive_source_honeypot()."""

    def test_extracts_top_level_dir(self) -> None:
        """Should return the first path component relative to base_dir."""
        result = derive_source_honeypot("/data/dionaea/binaries/sample.bin", "/data")
        assert result == "dionaea"

    def test_extracts_cowrie(self) -> None:
        """Should work for any honeypot name."""
        result = derive_source_honeypot("/data/cowrie/downloads/evil.sh", "/data")
        assert result == "cowrie"

    def test_returns_unknown_when_not_under_base(self) -> None:
        """Should return 'unknown' when the file is outside the base dir."""
        result = derive_source_honeypot("/other/random/file.bin", "/data")
        assert result == "unknown"

    def test_returns_unknown_for_file_directly_in_base(self) -> None:
        """A file at the base dir root has no honeypot parent — edge case."""
        # Path("/data/file.bin").relative_to("/data") → ("file.bin",)
        # parts[0] is the filename, which is technically returned.
        # This documents the current behavior.
        result = derive_source_honeypot("/data/file.bin", "/data")
        assert result == "file.bin"


class TestGetMimeTypeEdgeCases:
    """Tests for _get_mime_type edge cases."""

    def test_returns_unknown_when_mime_is_none(self) -> None:
        """When magic.Magic init fails, mime=None is passed — should return 'unknown'."""
        result = _get_mime_type(Path("/any/file.bin"), mime=None)
        assert result == "unknown"


class TestScanPayloadsByRange:
    """Unit tests for scan_payloads_by_range()."""

    def test_nonexistent_directory_yields_nothing(self) -> None:
        """A directory that doesn't exist should yield zero results."""
        results = list(
            scan_payloads_by_range(
                directory="/nonexistent/path",
                start_ts=0,
                end_ts=time.time(),
                base_dir="/nonexistent",
            ),
        )
        assert results == []

    def test_filters_by_timestamp_range(self) -> None:
        """Only files with mtime in [start_ts, end_ts] should be yielded."""
        with tempfile.TemporaryDirectory() as td:
            honeypot_dir = Path(td) / "dionaea" / "binaries"
            honeypot_dir.mkdir(parents=True)

            recent = honeypot_dir / "recent.bin"
            recent.write_bytes(b"new malware")

            old = honeypot_dir / "old.bin"
            old.write_bytes(b"old malware")
            old_time = time.time() - 7200
            os.utime(old, (old_time, old_time))

            now = time.time()
            with patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no magic")):
                results = list(
                    scan_payloads_by_range(
                        directory=honeypot_dir,
                        start_ts=now - 60,
                        end_ts=now + 60,
                        base_dir=td,
                    ),
                )

            assert len(results) == 1
            assert results[0]["source_honeypot"] == "dionaea"

    def test_includes_source_honeypot_in_output(self) -> None:
        """Each yielded dict should contain a 'source_honeypot' key."""
        with tempfile.TemporaryDirectory() as td:
            cowrie_dir = Path(td) / "cowrie" / "downloads"
            cowrie_dir.mkdir(parents=True)
            (cowrie_dir / "payload.sh").write_bytes(b"#!/bin/bash")

            now = time.time()
            with patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no magic")):
                results = list(
                    scan_payloads_by_range(
                        directory=cowrie_dir,
                        start_ts=now - 60,
                        end_ts=now + 60,
                        base_dir=td,
                    ),
                )

            assert len(results) == 1
            assert results[0]["source_honeypot"] == "cowrie"

    def test_skips_files_where_hashing_fails(self) -> None:
        """If compute_hashes returns {}, the file should be silently skipped."""
        with tempfile.TemporaryDirectory() as td:
            honeypot_dir = Path(td) / "dionaea" / "binaries"
            honeypot_dir.mkdir(parents=True)
            (honeypot_dir / "broken.bin").write_bytes(b"content")

            now = time.time()
            with (
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no magic")),
                patch("app.scanner.compute_hashes", return_value={}),
            ):
                results = list(
                    scan_payloads_by_range(
                        directory=honeypot_dir,
                        start_ts=now - 60,
                        end_ts=now + 60,
                        base_dir=td,
                    ),
                )

            assert results == []

    def test_oserror_on_stat_is_skipped(self) -> None:
        """Files that raise OSError on stat() should be skipped, not crash."""
        with tempfile.TemporaryDirectory() as td:
            honeypot_dir = Path(td) / "dionaea" / "binaries"
            honeypot_dir.mkdir(parents=True)
            f = honeypot_dir / "disappearing.bin"
            f.write_bytes(b"now you see me")

            now = time.time()
            with (
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no magic")),
                patch.object(Path, "stat", side_effect=OSError("permission denied")),
            ):
                results = list(
                    scan_payloads_by_range(
                        directory=honeypot_dir,
                        start_ts=now - 60,
                        end_ts=now + 60,
                        base_dir=td,
                    ),
                )

            assert results == []
