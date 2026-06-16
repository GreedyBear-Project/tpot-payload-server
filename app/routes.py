"""Payload API routes.

Defines the ``/api/v1/payloads`` router with two endpoints:

- ``GET /recent`` — metadata for recently modified honeypot payload files.
- ``GET /download/{locator:path}`` — raw binary download by relative locator.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse

from app.auth import verify_api_key
from app.config import BASE_DATA_DIR, HONEYPOT_DIRS
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

    logger.info("Found %d payloads in window [%s, %s]", len(results), start_ts, end_ts)
    return results


def _resolve_locator(locator: str) -> Path:
    """Resolve a relative locator to an absolute path, guarding against traversal.

    Args:
        locator: Relative path from ``BASE_DATA_DIR`` (e.g. ``dionaea/binaries/sample.bin``).

    Returns:
        Resolved absolute ``Path`` to the file.

    Raises:
        HTTPException: 422 if the locator attempts path traversal.
        HTTPException: 404 if the resolved path does not exist or is not a file.
    """
    base = Path(BASE_DATA_DIR).resolve()

    # Layer 1: reject obviously malicious locators before constructing any path.
    locator_path = Path(locator)
    if locator_path.is_absolute():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid locator — absolute paths are not allowed",
        )

    resolved = (base / locator_path).resolve()

    # Layer 2: resolved path must still be under BASE_DATA_DIR
    # (catches URL-encoded traversal like %2e%2e).
    if not resolved.is_relative_to(base):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid locator — path traversal detected",
        )

    if not resolved.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No payload found at locator: {locator}",
        )

    return resolved


@router.get(
    "/download/{locator:path}",
    summary="Download a payload by locator",
    description=("Stream the raw bytes of a payload file identified by its relative locator (returned by the /recent endpoint)."),
    responses={
        200: {"content": {"application/octet-stream": {}}},
        404: {"description": "Payload not found"},
        422: {"description": "Invalid locator"},
    },
)
def download_payload(
    locator: str,
    _api_key: Annotated[str | None, Depends(verify_api_key)],
) -> FileResponse:
    """Stream the raw bytes of a payload identified by its relative locator.

    The locator is the relative path from ``BASE_DATA_DIR`` to the file,
    as returned by the ``/recent`` endpoint's ``locator`` field.

    Args:
        locator: Relative file path (e.g. ``dionaea/binaries/sample.bin``).
        _api_key: Injected by the auth dependency; unused in logic.

    Returns:
        A streaming file response with ``application/octet-stream`` content type.

    Raises:
        HTTPException: 422 if the locator attempts path traversal.
        HTTPException: 404 if no file exists at the resolved path.
    """
    file_path = _resolve_locator(locator)

    return FileResponse(
        path=str(file_path),
        media_type="application/octet-stream",
        filename=file_path.name,
    )
