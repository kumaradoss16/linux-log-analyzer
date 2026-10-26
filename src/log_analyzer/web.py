from __future__ import annotations

import argparse
import json
import re
import shutil   # Removes the temporary upload directory
import tempfile   # Creates a temporary upload directory
import threading   # Provides a lock for shared file state
import uuid   # Generates unique file identifiers
import warnings
import webbrowser   # Opens the dashboard in a browser when requested
from dataclasses import dataclass
from http import HTTPStatus   # Provides named HTTP status codes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path   # Represent filesystem paths
from typing import Any
from urllib.parse import parse_qs, urlparse   # Parse URL paths and query parameters

from . import __version__
from .analyzer import Analyzer, LogReadError
from .models import Source
from .report import render_json, render_text

# Configuration constants
STATIC_DIR = Path(__file__).parent / "static"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf=8"),
}

MAX_UPLOAD_BYTES = 200 * 1024 * 1024   # 200 MB
LOOPBACK = {"127.0.0.1", "localhost", "::1"}   # List the local-host names and addresses.


# Log file registered in the dashboard workspace
@dataclass   # Automatically generates useful methods, including an initializer.
class LogFile:
    id: str
    source: Source
    name: str
    path: Path
    uploaded: bool

    # Creates a dictionary containing information suitable for sending to the browser.
    def describe(self) -> dict:
        try:
            size = self.path.stat().st_size   # Retrieves the file size in bytes
        except OSError:
            size = None

        return {
            "id": self.id,
            "source": self.source.value,
            "name": self.name,
            "size": size,
            "uploaded": self.uploaded
        }


# Central Manager for the dashboard's loaded log files.
class Workspace:
    def __init__(self, year: int | None) -> None:
        self.year = year
        self._files: dict[str, LogFile] = {}   # Stores LogFile object in a dict keyed by the file ID.
        self._lock = threading.Lock()   # Protects shared file-registry operations from concurrent modification.
        self._tmp = Path(tempfile.mkdtemp(prefix="logan-"))   # Creates a temporary directory for uploaded logs.


    # Register an existing log file in the workspace
    def add_path(self, source: Source, path: Path) -> LogFile:
        with self._lock:
            for f in self._files.values():
                if f.source is source and f.path == path:
                    return f

            lf = LogFile(
                uuid.uuid4().hex[:8],
                source,
                path.name,
                path,
                uploaded=False,
            )
            self._files[lf.id] = lf
            return lf


    # Creates a safe destination for an upload
    def new_upload_path(self, filename: str) -> tuple[str, Path]:
        safe = re.sub(
            r"[^A-Za-z0-9._-]",
            "_",
            Path(filename).name   # Extracts the filename component
        )[:100] or "uploade.log"

        fid = uuid.uuid4().hex[:8]
        return fid, self._tmp / f"{fid}_{safe}"


    # Register an uploaded file
    def register_upload(self, fid: str, source: Source, filename: str, path: Path,) -> LogFile:
        lf = LogFile(
            fid,
            source,
            Path(filename).name[:100] or "upload.log",
            path,
            uploaded=True,
        )

        with self._lock:
            self._files[fid] = lf

        return lf


    # Remove one file (removes an entry from the workspace registry)
    def remove(self, fid: str) -> bool:
        with self._lock:
            lf = self._files.pop(fid, None)

        if lf and lf.uploaded:
            lf.path.unlink(missing_ok=True)

        return lf is not None


    # Clear the workspace (Remove all registered entries)
    def clear(self) -> None:
        with self._lock:
            files, self._files = list(self._files.values()), {}

        for lf in files:
            if lf.uploaded:
                lf.path.unlink(missing_ok=True)


    # List registered files (list of file metadata dictionaries
    def list(self) -> list[dict]:
        with self._lock:
            return [f.describe() for f in self._files.values()]


    # Workspace's main analysis operation
    def analyze(self, top: int, threshold: int, year: int | None) -> dict:
        with self._lock:
            files = list(self._files.values())

            analyzer = Analyzer(year=year or self.year)
            warnings: list[str] = []

            for lf in files:
                try:
                    analyzer.ingest_file(lf.source, lf.path)
                except LogReadError as exc:
                    warnings.append(str(exc))

            data = analyzer.to_dict(top=top, threshold=threshold)
            data["files"] = [f.describe() for f in files]
            data["warnings"] = warnings
            data["year"] = analyzer.year
            return data


    # Clean up temporary storage
    def close(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)   # to ignore cleanup errors.


# Helper functions
def _find_samples(self) -> Path | None:
    for cand in (Path(__file__).resolve().parents[2] / "samples", Path.cwd() / "samples"):
        if cand.is_dir():
            return cand
        return None

# Read and validate an integer URL parameter
def _int_param(q: dict, name: str, default: int | None, lo: int, hi: int) -> int | None:
    raw = q.get(name, [""])[0]
    if raw == "":
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return default


# Processing HTTP requests
class Handler(BaseHTTPRequestHandler):
    server: "Dashboard Server"
    server_version = f"logan/{__version__}"

    # Control HTTP server logging
    def log_message(self, fmt: str, *args) -> None:
        # quieter than the default
        if self.server.verbose:   # checks whether verbose loggig is enabled.
            super().log_message(fmt, *args)

    # Build and send an HTTP response
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")   # Request that the browser and other caches do not store the response
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)

        self.end_headers()
        self.wfile.write(body)   # writes the response bytes to the connection

    # Send a JSON response
    def _json(self, obj: object, status: int = 200) -> None:
        self._send(status, json.dumps(obj, default=str).encode(), "application/json")

    # Return a consistent error response
    def _error(self, status: int, msg: str) -> None:
        self._json({"error": msg}, status)

    # Validate the HTTP Host header
    def _host_ok(self) -> bool:
        allowed = self.server.allowed_hosts

        if allowed is None:
            return True

        host = (self.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        return host in allowed

    # Check requests that modify data
    def _mutation_ok(self) -> bool:
        return self.headers.get("X-Logan") == "1"

    # retrieve dashboard resources and reports.
    def do_GET(self) -> None:
        # Validate the Host header
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
        url = urlparse(self.path)
        q = parse_qs(url.query)
        ws = self.server.workspace

        # Server static Files
        if url.path in STATIC_FILES:
            name, ctype = STATIC_FILES[url.path]
            return self._send(200, (STATIC_DIR / name). read_bytes(), ctype)
        # Return the registered log files
        if url.path == "/api/files":
            return self._json({"files": ws.list()})
        # Generate a report
        if url.path in ("/api/report", "/api/report.txt"):
            data = ws.analyze(
                top=_int_param(q, "top", 10, 1, 100),
                threshold=_int_param(q, "threshold", 5, 1, 100000),
                year=_int_param(q, "year", None, 1970, 2100)
            )
            if url.path == "/api/report":
                return self._json(data)
            return self._send(200, render_text(data).encode(), "text/plain; charset=utf-8", {"Content-Disposition": 'attachment; filename="log-report.txt"'})
        if url.path == "/api/report.json":
            data = ws.analyze(
                top=_int_param(q, "top", 10, 1, 100),
                threshold=_int_param(q, "threshold", 5, 1, 100000),
                year=_int_param(q, "year", None, 1970, 2100)
            )
            if url.path == "/api/report":
                return self._json(data)
            return self._send(200, render_json(data).encode(), "application/json",{"Content-Disposition": 'attachment; filename="log-report.json"'})
        self._error(HTTPStatus.NOT_FOUND, "not found")


    # Handle operations that change the workspace (create, upload or change workspace state)
    def do_POST(self) -> None:
        # Check the host and custom header
        if not self._host_ok():
            return self._error(
            HTTPStatus.FORBIDDEN,
            "bad Host header"
        )

        if not self._mutation_ok():
            return self._error(
            HTTPStatus.FORBIDDEN,
            "missing X-Logan header"
        )

        # Parse the request URl
        url = urlparse(self.path)
        q = parse_qs(url.query)
        ws = self.server.workspace

        # Dispatch the uploade route
        if url.path == "/api/upload":
            return self._upload(q)

        # Clear the workspace
        if url.path == "/api/clear":
            ws.clear()
            return self._json({"ok": True})

        # Load sample logs
        if url.path == "/api/samples":
            samples = _find_samples()

            if samples is None:
                return self._error(
                    HTTPStatus.NOT_FOUND,
                    "samples/ directory not found"
                )
            added = 0
            for src, name in (
                (Source.AUTH, "auth.log"),
                (Source.SYSTEM, "syslog"),
                (Source.WEB, "access.log")
            ):
                if (samples / name).is_file():
                    ws.add_path(src, samples / name)
                    added += 1

            return self._json({"added": added})









