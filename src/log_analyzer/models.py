from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# Defines the possible sources of an event
class Source(str, Enum):
    AUTH = "auth"
    SYSTEM = "system"
    WEB = "web"

# Defines what happened during an event
class Kind(str, Enum):
    LOGIN_FAILED = "login failed"
    LOGIN_SUCCESS = "login_success"
    ERROR = "error"
    REQUEST = "request"


@dataclass(frozen=True, slots=True)
class Event:
    """A normalized event produced by any parser."""

    source: Source
    kind: Kind
    timestamp: datetime | None = None
    ip: str | None = None
    user: str | None = None
    detail: str = ""    # process name (system), path (web), auth method (auth)
    status: int | None = None   # HTTP status for web events


