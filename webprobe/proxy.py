"""Proxy launcher - starts mitmdump with our addon."""

import os
import signal
import subprocess
import sys
from pathlib import Path


def start_proxy(
    db_path: str,
    listen_port: int = 8080,
    listen_host: str = "127.0.0.1",
    upstream_proxy: str = None,
    ssl_insecure: bool = False,
    quiet: bool = False,
    transparent: bool = False,
    scope_filter: str = None,
):
    addon_path = Path(__file__).parent / "proxy_addon.py"

    env = os.environ.copy()
    env["WEBPROBE_DB"] = str(db_path)

    cmd = [
        "mitmdump",
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "-s", str(addon_path),
        "--set", "flow_detail=0",  # reduce mitmdump's own output
    ]

    if ssl_insecure:
        cmd.append("--ssl-insecure")

    if transparent:
        cmd.append("--mode")
        cmd.append("transparent")

    if upstream_proxy:
        cmd.extend(["--mode", f"upstream:{upstream_proxy}"])

    if scope_filter:
        cmd.extend(["--allow-hosts", scope_filter])

    if quiet:
        cmd.extend(["-q"])

    return cmd, env
