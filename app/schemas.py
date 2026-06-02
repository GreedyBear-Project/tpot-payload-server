"""Pydantic response models for the payload API.

These schemas define the JSON contract between tpot-payload-server and
its consumers (primarily GreedyBear's ``extract_honeypot_payloads`` task).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PayloadMetadata(BaseModel):
    """Metadata extracted from a single honeypot payload file.

    Attributes:
        mime_type: MIME type detected by python-magic.
        md5: MD5 hex digest.
        sha1: SHA-1 hex digest.
        sha256: SHA-256 hex digest.
        mtime: File modification time as a Unix timestamp.
        size: File size in bytes.
        source_honeypot: Honeypot name derived from the file path.
    """

    mime_type: str
    md5: str
    sha1: str
    sha256: str
    mtime: float
    size: int = Field(ge=0)
    source_honeypot: str
