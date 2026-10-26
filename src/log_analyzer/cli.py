from __future__ import annotations

import argparse    # Defines and parses command-line arguments
import sys
from pathlib import Path

from . import __version__, analyzer
from .analyzer import Analyzer, LogReadError
from .models import Source
from .report import render_json, render_text

# Create the command-line options
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="login",
        description="Analyze Linux auth/system/web logs."
    )
    # Accepts one or more authentication log file paths.
    p.add_argument(
        "--auth",
        nargs="+",
        type=Path,
        default=[],
        metavar="FILE",
        help="auth logs (e.g. /var/log/auth.log, /var/log/secure; .gz ok0"
    )
    # Specifies system log files.
    p.add_argument(
        '--system',
        nargs="+",
        type=Path,
        default=[],
        metavar="FILE",
        help="system logs (e.g. /var/log/syslog, /var/log/messages0"
    )
    # Specifies web-server access logs
    p.add_argument(
        "--web",
        nargs="+",
        type=Path,
        default=[],
        metvar="FILE",
        help="Apache/Nginx access logs (combined format)"
    )
    # Controls how many results are included in top-N lists
    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="rows per top-N table (default 10)"
    )
    # Controls the no. of failed login attempts from a single IP address required to trigger the analyzer's brute-force indicator.
    p.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="failed logins from one IP before it is flagged (default 5)"
    )
    p.add_argument(
        "--year",
        type=int,
        default=None,
        help="year for syslog timestamps, which omit it (default current year)"
    )
    # Select the report format
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text"
    )
    # Allow the user to save the report to a file.
    p.add_argument(
        "-o", "--output",
        type=Path,
        help="write report to file instead of stdout."
    )
    # Displays the installed package version and exits
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    return p   # returning the parser


# Controlling program execution
# argv - optionally accepts a list of CLI arguments
def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Check whether the user requested the dashboard
    if argv and argv[0] == "serve":
        from .web import main as web_main

        return web_main(argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.auth or args.system or args.web):
        parser.error("provide at least one of --auth, --system, --web")
    analyzer = Analyzer(year=args.year)

    # Ingest the selected log files
    try:
        analyzer.ingest_files(Source.AUTH, args.auth)
        analyzer.ingest_files(Source.SYSTEM, args.system)
        analyzer.ingest_files(Source.WEB, args.web)
    except LogReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Generate the analysis results
    data = analyzer.to_dict(
        top=args.top,
        threshold=args.threshold
    )

    # Select the output format
    text = render_json(data) if args.format == "json" else render_text(data)

    # Write the report to a file or print it
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text, end='')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())




