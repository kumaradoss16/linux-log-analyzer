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
from operator import length_hint
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
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
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
def _find_samples() -> Path | None:
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
    server: "DashboardServer"
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
        self._error(HTTPStatus.NOT_FOUND, "not_found")


    # Remove a registered log file
    def do_DELETE(self) -> None:
        # Apply request checks
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

        # Match the file-removal endpoints
        url = urlparse(self.path)
        if url.path == "/api/files":
            fid = parse_qs(url.query).get("id", [""])[0]
            # Attempt to remove the file
            if self.server.workspace.remove(fid):
                return self._json({"ok": True})

            return self._error(
                HTTPStatus.NOT_FOUND,
                "no such file"
            )
        self._error(HTTPStatus.NOT_FOUND, "not found")


    def _upload(self, q: dict) -> None:
        # Validate the log source
        try:
            source = Source(q.get("source", [""])[0])
        except ValueError:
            return self._error(HTTPStatus.BAD_REQUEST, "source must be auth, system or web")

        # Read the filename
        filename = q.get("filename", ["upload.log"])[0]

        # Read and validate Content-Length
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")

        # Enforce the upload-size limit
        if length > MAX_UPLOAD_BYTES:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"max uploaded is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")

        # Prepare the uploaded destination
        """
        ws - workspace that manages registered log files
        fid - identifier assigned to the uploaded file
        dest - Path object representing the destination file
        """
        ws = self.server.workspace
        fid, dest = ws.new_upload_path(filename)

        # Preserve the .gz extension for compresses logs
        if filename.lower().endswith(".gz"):
            if dest.suffix != ".gz":
                dest = dest.with_name(dest.name + ".gz")

        # Stream the uploaded data to disk
        remaining = length
        with dest.open("wb") as out:
            # Read data in chunks
            while remaining > 0:
                # rfile -> HTTP request input stream
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)

            # Detect an incomplete upload
            if remaining:
                dest.unlink(missing_ok=True)
                return self._error(HTTPStatus.BAD_REQUEST, "upload truncated")
             # Register the uploaded file
            lf = ws.register_upload(fid, source, filename, dest)
            self._json(lf.describe(), HTTPStatus.CREATED)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], workspace: Workspace, verbose: bool = False) -> None:
        super().__init__(addr, Handler)
        self.workspace = workspace
        self.verbose = verbose
        self.allowed_hosts: set[str] | None = (LOOPBACK if addr[0] in LOOPBACK else None)


# Defines the CLI for starting the dashboard
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logan serve", description="Log analyzer web dashboard.")
    for name in ("auth", "system", "web"):
        p.add_argument(f"--{name}", nargs="+", type=Path, default=[], metavar="FILE", help=f"preload {name} log(s); re-read on every refresh")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    p.add_argument("--year", type=int, default=None, help="year for syslog timestamps")
    p.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    p.add_argument("-v", "--verbose", action="store_true", help="log HTTP requests")
    return p


# Coordinates the application's startup, runtime and shutdown
def main(argv: list[str] | None = None) -> int:
    # Parse the arguments
    args = build_parser().parse_args(argv)
    ws = Workspace(year=args.year)

    # Register the supplied log files
    for source, paths in ((Source.AUTH, args.auth), (Source.SYSTEM, args.system), (Source.WEB, args.web)):
        for path in paths:
            if not path.is_file():
                print(f"error: not a file: {path}")
                return 2
            ws.add_path(source, path)

    # Create the HTTP server
    server = DashboardServer((args.host, args.port), ws, verbose=args.verbose)
    url = f"http://{args.host}:{server.server_address[1]}/"
    print(f"Log Analyzer dashboard running at {url} (Ctrl+C to stop)")

    # Display a network exposure warning
    if args.host not in LOOPBACK:
        print("WARNING: bound to a non-loopback address. The dashboard has no authentication and "
              "exposes the log files you load; put it behind a trusted network or proxy.")

    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n Shutting down.")
    finally:
        server.server_close()
        ws.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
