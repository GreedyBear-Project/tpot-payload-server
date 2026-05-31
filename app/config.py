"""Application settings loaded from environment variables.

All configuration is read from environment variables at import time.
This keeps the service stateless and 12-factor compliant.
"""

from __future__ import annotations

import os

# API authentication key.
# When empty or unset, authentication is disabled.
API_KEY: str = os.getenv("API_KEY", "")

# Root directory where honeypot data volumes are mounted.
# In production this is typically /data, matching the docker-compose
# volume mount targets.
DATA_BASE_DIR: str = os.getenv("DATA_BASE_DIR", "/data")

# Comma-separated list of honeypot subdirectory names under DATA_BASE_DIR.
# Each entry corresponds to a mounted honeypot data directory, e.g.
# "dionaea/binaries,cowrie/downloads,honeytrap/downloads,adbhoney/downloads".
HONEYPOT_DIRS: list[str] = [
    d.strip()
    for d in os.getenv(
        "HONEYPOT_DIRS",
        "dionaea/binaries,cowrie/downloads,honeytrap/downloads,adbhoney/downloads",
    ).split(",")
    if d.strip()
]
