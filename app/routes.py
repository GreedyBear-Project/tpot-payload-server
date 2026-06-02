"""Payload API routes.

Defines the ``/api/v1/payloads`` router with two endpoints:

- ``GET /recent`` — metadata for recently modified honeypot payload files.
- ``GET /download/{sha256}`` — raw binary download by SHA-256 hash.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse

from app.auth import verify_api_key
from app.config import BASE_DATA_DIR, HONEYPOT_DIRS
from app.hasher import compute_hashes
from app.scanner import scan_payloads_by_range
from app.schemas import PayloadMetadata

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/payloads", tags=["payloads"])


@router.get(
    "/recent",
    response_model=list[PayloadMetadata],
    summary="List recently modified payloads",
    description=("Scan all configured honeypot directories for files whose modification time falls within the given time window and return their metadata."),
)
def list_recent_payloads(
    start_ts: Annotated[float, Query(description="Start of the time window (Unix timestamp, inclusive)")],
    end_ts: Annotated[float, Query(description="End of the time window (Unix timestamp, inclusive)")],
    _api_key: Annotated[str | None, Depends(verify_api_key)],
) -> list[dict]:
    """Return metadata for files modified between start_ts and end_ts.

    Args:
        start_ts: Unix timestamp for the start of the scan window.
        end_ts: Unix timestamp for the end of the scan window.
        _api_key: Injected by the auth dependency; unused in logic.

    Returns:
        A list of payload metadata dictionaries.
    """
    if start_ts > end_ts:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="start_ts must be less than or equal to end_ts",
        )

    results: list[dict] = []

    for honeypot_subdir in HONEYPOT_DIRS:
        scan_dir = Path(BASE_DATA_DIR) / honeypot_subdir
        results.extend(
            scan_payloads_by_range(
                directory=scan_dir,
                start_ts=start_ts,
                end_ts=end_ts,
                base_dir=BASE_DATA_DIR,
            ),
        )

    # Populate the hash→path cache so subsequent /download calls are O(1).
    for payload in results:
        _hash_path_cache[payload["sha256"]] = Path(payload["file_path"])

    logger.info("Found %d payloads in window [%s, %s]", len(results), start_ts, end_ts)
    return results


# In-process cache mapping SHA-256 → file path, populated by /recent scans.
# Validated with Path.exists() before use to guard against stale entries.
_hash_path_cache: dict[str, Path] = {}


def _find_file_by_sha256(sha256: str) -> Path | None:
    """Look up a file by SHA-256, checking the cache first.

    The cache is populated by ``list_recent_payloads``.  On a cache hit
    the path is validated with ``Path.exists()`` to handle files that
    were deleted since the last scan.  On a miss, falls back to a full
    directory scan.

    Args:
        sha256: SHA-256 hex digest to search for.

    Returns:
        Path to the matching file, or ``None`` if not found.
    """
    # Fast path: check cache
    cached = _hash_path_cache.get(sha256)
    if cached and cached.exists():
        return cached

    # Cache miss — fall back to full scan
    for honeypot_subdir in HONEYPOT_DIRS:
        scan_dir = Path(BASE_DATA_DIR) / honeypot_subdir
        if not scan_dir.is_dir():
            continue
        for file_path in scan_dir.rglob("*"):
            if not file_path.is_file():
                continue
            hashes = compute_hashes(file_path)
            if hashes and hashes.get("sha256") == sha256:
                _hash_path_cache[sha256] = file_path
                return file_path
    return None


@router.get(
    "/download/{sha256}",
    summary="Download a payload by SHA-256",
    description="Stream the raw bytes of a payload file identified by its SHA-256 hash.",
    responses={
        200: {"content": {"application/octet-stream": {}}},
        404: {"description": "Payload not found"},
    },
)
def download_payload(
    sha256: str,
    _api_key: Annotated[str | None, Depends(verify_api_key)],
) -> FileResponse:
    """Stream the raw bytes of a payload identified by its SHA-256 hash.

    Args:
        sha256: SHA-256 hex digest of the requested file.
        _api_key: Injected by the auth dependency; unused in logic.

    Returns:
        A streaming file response with ``application/octet-stream`` content type.

    Raises:
        HTTPException: 404 if no file with the given SHA-256 exists.
    """
    if len(sha256) != 64:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid SHA-256 hash — must be exactly 64 hex characters",
        )

    try:
        int(sha256, 16)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid SHA-256 hash — must contain only hex characters",
        ) from None

    file_path = _find_file_by_sha256(sha256)
    if file_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No payload found with SHA-256: {sha256}",
        )

    return FileResponse(
        path=str(file_path),
        media_type="application/octet-stream",
        filename=f"{sha256}.bin",
    )
