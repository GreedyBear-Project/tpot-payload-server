"""API key authentication dependency for FastAPI.

When the ``API_KEY`` environment variable is set, every protected endpoint
requires the caller to send a matching ``X-API-Key`` header.  When it is
empty or unset, authentication is disabled entirely.
"""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import API_KEY

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str | None:
    """Validate the API key from the request header.

    Args:
        api_key: Value of the ``X-API-Key`` header, injected by FastAPI.

    Returns:
        The validated API key string, or ``None`` when auth is disabled.

    Raises:
        HTTPException: 403 if a key is configured but the request supplies
            a missing or incorrect key.
    """
    # No key configured → auth disabled
    if not API_KEY:
        return None

    if not api_key or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
        )
    return api_key
