"""Reads the files, aggregates the events, and generates a report."""
from __future__ import annotations

import gzip  # Reads compressed .gz log files
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path   # Represent filesystem paths

from .models import Event, Kind, Source
from .parsers import PARSERS

# Defines a custom exception for log-file reading failures.
class LogReadError(Exception):
    """Raised when a log file cannot be opened or read."""


# Reads a normal text log file or a gzip-compressed log file
def read_lines(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\n")
    except OSError as exc:
        raise LogReadError(f"Cannot read {path}: {exc}") from exc


# Holds the application's analysis state.from
class Analyzer:
    def __init__(self, year: int | None) -> None:
        self.year = year or datetime.now().year
        self.lines_read: Counter[str] = Counter()   # Tracks the number of lines read
        # Tracking the first and last event timestamps
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None

        self.failed_by_ip: Counter[str] = Counter()
        self.failed_by_user: Counter[str] = Counter()
        self.success_by_ip: Counter[str] = Counter()
        self.success_by_user: Counter[str] = Counter()
        self.auth_methods: Counter[str] = Counter()

        self.web_ips: Counter[str] = Counter()
        self.web_status: Counter[int] = Counter()
        self.web_error_paths: Counter[str] = Counter()
        self.system_errors_by_proc: Counter[str] = Counter()

        self.hourly: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
        self.daily: Counter[str] = Counter()

    # Connects the file reader, parser registry, and analyzer
    def ingest_file(self, source: Source, path: Path) -> None:
        parse = PARSERS[source]
        for line in read_lines(path):
            if not line.strip():
                continue
            self.lines_read[source.value] += 1
            event = parse(line, self.year)
            if event is not None:
                self.add(event)

    # Iterable of file paths and processes each one using ingest_file()
    def ingest_files(self, source: Source, paths: Iterator[Path]) -> None:
        for p in paths:
            self.ingest_file(source, p)


    # Receives one normalized event and updates the relevant counters.
    def add(self, e: Event) -> None:
        self._track_time(e)
        if e.kind is Kind.LOGIN_FAILED:
            self.failed_by_ip[e.ip or "?"] += 1
            self.failed_by_user[e.user or "?"] += 1
            self.auth_methods[e.detail] += 1
        elif e.kind is Kind.LOGIN_SUCCESS:
            self.success_by_ip[e.ip or "?"] += 1
            self.success_by_user[e.user or "?"] += 1
            self.auth_methods[e.detail] += 1
        elif e.kind is Kind.ERROR:
            self.system_errors_by_proc[e.detail] += 1
        elif e.kind is Kind.REQUEST:
            self.web_ips[e.ip or "?"] += 1
            if e.status is not None:
                self.web_status[e.status] += 1
                if e.status >= 400:
                    self.web_error_paths[f"{e.status} {e.detail}"] += 1


    # Checking whether the event has a valid timestamp.
    def _track_time(self, e: Event) -> None:
        if e.timestamp is None:
            return
        ts = e.timestamp   # Stores the event timestamp in a local variable
        naive = ts.replace(tzinfo=None)   # Removes the timezone info without converting the local time
        # Update the first and last timestamps
        self.first_seen = (
            naive if self.first_seen is None
            else min(self.first_seen, naive)
        )
        self.last_seen = (
            naive if self.last_seen is None
            else max(self.last_seen, naive)
        )
        # Assign the event to an hourly metric
        metric = {
            Kind.LOGIN_FAILED: "failed_logins",
            Kind.LOGIN_SUCCESS: "successful_logins",
            Kind.ERROR: "system_errors",
            Kind.REQUEST: "web_errors" if (e.status or 0) >= 400 else "web_requests",
        }[e.kind]
        self.hourly[metric][ts.hour] += 1
        self.daily[naive.date().isoformat()] += 1


    # Converts the accumulated statistics into a nested Python dictionary.
    def to_dict(self, top: int = 10, threshold: int = 5) -> dict:
        web_4xx = sum(c for s, c in self.web_status.items() if 400 <= s < 500)
        web_5xx = sum(c for s, c in self.web_status.items() if s >= 500)
        sys_errors = sum(self.system_errors_by_proc.values())

        # Combine IP address counts
        all_ips: Counter[str] = Counter()
        for c in (
            self.failed_by_ip,
            self.success_by_ip,
            self.web_ips
        ):
            all_ips.update(c)
        all_users = self.failed_by_user + self.success_by_user  # Combine username counts
        # Identify possible brute-force activity
        brute_force = {
            ip: n
            for ip, n in self.failed_by_ip.items() if n >= threshold
        }
        possible_compromise = sorted(
            ip for ip in brute_force
            if ip in self.success_by_ip
        )

        return {
            "summary": {
                "lines_read": dict(self.lines_read),
                "first_event": self.first_seen.isoformat() if self.first_seen else None,
                "last_event": self.last_seen.isoformat() if self.last_seen else None,
            },
            "logins": {
                "failed": sum(self.failed_by_ip.values()),
                "successful": sum(self.success_by_ip.values()),
                "failed_by_ip": self.failed_by_ip.most_common(top),
                "failed_by_user": self.failed_by_user.most_common(top),
                "successful_by_user": self.success_by_user.most_common(top),
                "successful_by_ip": self.success_by_ip.most_common(top),
                "methods": dict(self.auth_methods)
            },
            "web": {
                "requests": sum(self.web_status.values()),
                "status_codes": {
                    str(k): v
                    for k, v in sorted(self.web_status.items())
                },
                "status_code": {
                    str(k): v
                    for k, v in sorted(self.web_status.items())
                },
            },
            "top_source_ips": all_ips.most_common(top),
            "top_users": all_users.most_common(top),
            "errors": {
                "total": sys_errors + web_4xx + web_5xx,
                "system": sys_errors,
                "web_4xx": web_4xx,
                "web_5xx": web_5xx,
                "system_by_process": self.system_errors_by_proc.most_common(top),
                "web_by_status_path": self.web_error_paths.most_common(top),
            },
            "time_distribution": {
                "hourly": {
                    k: v for k, v in sorted(self.hourly.items())
                },
                "daily": dict(sorted(self.daily.items())),
            },
            "alerts": {
                "threshold": threshold,
                "brute_force_ips": sorted(
                    brute_force.items(),
                    key=lambda kv: -kv[1]
                ),
                "possible_compromise_ips": possible_compromise
            },
        }
