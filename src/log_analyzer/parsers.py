from  __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime

from .models import Event, Kind, Source

# syslog header pattern
_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
# IP address pattern
_IP = r"[0-9a-fA-F:.]+"
# failed-login pattern
_FAILED_RE = re.compile(
    rf"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IP})"
)
# successful-login pattern
_ACCEPTED_RE = re.compile(
    rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>{_IP})"
)
# system error pattern
_ERROR_RE = re.compile(
    r"\b(error|errors|fail|failed|failure|critical|crit|alert|emerg|panic|segfault|"
    r"oom-killer|out of memory|denied|timeout|timed out)\b",
    re.IGNORECASE,
)
# web access log pattern
_WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+'
)

# Converts a timestamp string into a Python datetime object
def _parse_syslog_ts(raw: str, year: int) -> datetime | None:
    try:
        if raw[0].isdigit():
            return datetime.fromisoformat(raw)
        return datetime.strptime(
            f"{year} {' '.join(raw.split())}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

# SSH authentication events in syslog-style lines
def parse_auth_line(line: str, year: int) -> Event | None:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None

    msg = m["msg"]
    ts = _parse_syslog_ts(m["ts"], year)

    if (f := _FAILED_RE.search(msg)) is not None:
        return Event(
            Source.AUTH, Kind.LOGIN_FAILED,
            ts, f["ip"], f["user"], f["method"]
        )

    if (a := _ACCEPTED_RE.search(msg)) is not None:
        return Event(
            Source.AUTH, Kind.LOGIN_SUCCESS,
            ts, a["ip"], a["user"], a["method"]
        )

    return None

# Searches system log lines for error-related keywords
def parse_system_line(line: str, year: int) -> Event | None:
    m = _SYSLOG_RE.match(line)
    if not m or not _ERROR_RE.search(m["msg"]):
        return None

    # Create a system ERROR event
    return Event(
        Source.SYSTEM,
        Kind.ERROR,
        _parse_syslog_ts(m["ts"], year),
        detail=m["proc"]
    )

# Parses HTTP access logs produced in a supported Apache/Nginx common or combined-style format.
def parse_web_line(line: str, year: int) -> Event | None:
    m = _WEB_RE.match(line)
    if not m:
        return None

    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = None

    user = None if m["user"] == "-" else m["user"]

    return Event(
        Source.WEB,
        Kind.REQUEST,
        ts,
        m["ip"],
        user,
        m["path"],
        int(m["status"])
    )

# Parser registry
PARSERS: dict[Source, Callable[[str, int], Event | None]] = {
    Source.AUTH: parse_auth_line,
    Source.SYSTEM: parse_system_line,
    Source.WEB: parse_web_line,
}
