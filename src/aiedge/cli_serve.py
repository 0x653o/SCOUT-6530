"""HTTP report server for CLI ``serve`` subcommand."""

from __future__ import annotations

import functools
import sys
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import cast


def _serve_report_directory(
    *,
    run_dir_path: str,
    host: str,
    port: int,
    once: bool,
    duration_s: float | None,
) -> int:
    run_dir = Path(run_dir_path).expanduser().resolve()
    report_dir = run_dir / "report"
    viewer_path = report_dir / "viewer.html"

    if not run_dir.is_dir():
        print(f"Run directory not found: {run_dir}", file=sys.stderr)
        return 20
    if not report_dir.is_dir():
        print(f"Report directory not found: {report_dir}", file=sys.stderr)
        return 20
    if not viewer_path.is_file():
        print(
            f"Viewer file not found: {viewer_path} (run analyze first)",
            file=sys.stderr,
        )
        return 20

    if port < 0 or port > 65535:
        print("Invalid --port value: must be in range 0..65535", file=sys.stderr)
        return 20

    if duration_s is not None and duration_s <= 0:
        print("Invalid --duration-s value: must be > 0", file=sys.stderr)
        return 20

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(report_dir))
    try:
        httpd = HTTPServer((host, int(port)), handler)
    except OSError as e:
        print(f"Failed to start report server: {e}", file=sys.stderr)
        return 20

    with httpd:
        bound_host = cast(str, httpd.server_address[0])
        bound_port = int(httpd.server_address[1])
        print(
            f"http://{bound_host}:{bound_port}/viewer.html",
            flush=True,
        )
        try:
            if once:
                httpd.handle_request()
                return 0
            if duration_s is not None:
                deadline = time.monotonic() + float(duration_s)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    httpd.timeout = min(1.0, max(0.05, remaining))
                    httpd.handle_request()
                return 0
            httpd.serve_forever()
        except KeyboardInterrupt:
            return 0

    return 0
