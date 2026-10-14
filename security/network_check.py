import csv
import ctypes
import ipaddress
import subprocess
from ctypes import wintypes
from pathlib import Path

from core.scanner import scan_path
from security.startup_check import RISKY_PARTS, SCRIPT_HOSTS, SEVERITY

NO_WINDOW = subprocess.CREATE_NO_WINDOW     # keeps console windows from flashing
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    135: "Windows RPC", 139: "NetBIOS", 443: "HTTPS", 445: "File sharing (SMB)",
    1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 27017: "MongoDB",
}

# Ports that are risky when reachable from other machines.
RISKY_PORTS = frozenset({21, 23, 1433, 3306, 3389, 5432, 5900, 5985, 6379, 27017})

# ---------- Windows API: find a program's path from its process ID ----------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Declaring the types stops 64-bit handles from being silently truncated.
kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = (
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
)
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)


def process_path(pid):
    """Full path of a running program, or '' if Windows won't tell us."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)

    if not handle:
        return ""

    try:
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)

        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value

        return ""

    finally:
        kernel32.CloseHandle(handle)


# ---------- Reading connections ----------

def _run(command, timeout):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        creationflags=NO_WINDOW,
    ).stdout


def process_names():
    """PID -> program name, for processes we can't open directly."""
    try:
        output = _run(["tasklist", "/fo", "csv", "/nh"], 15)
    except (OSError, subprocess.SubprocessError):
        return {}

    names = {}

    for row in csv.reader(output.splitlines()):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]

    return names


def split_address(address):
    """'[::1]:5000' -> ('::1', 5000);  '10.0.0.5:443' -> ('10.0.0.5', 443)."""
    host, _, port = address.rpartition(":")
    return host.strip("[]"), int(port) if port.isdigit() else 0


def read_connections():
    rows = []

    for line in _run(["netstat", "-ano"], 30).splitlines():
        parts = line.split()

        if len(parts) < 5 or parts[0] != "TCP" or not parts[4].isdigit():
            continue

        local, remote, pid = parts[1], parts[2], int(parts[4])
        _, remote_port = split_address(remote)

        # The state word ("LISTENING") is translated on non-English Windows,
        # so we detect listeners by their empty remote address instead.
        rows.append({
            "kind": "Listening" if remote_port == 0 else "Connected",
            "local": local,
            "remote": remote,
            "pid": pid,
        })

    return rows


def _ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


# ---------- Judging ----------

def analyze(row, names, paths):
    kind, pid = row["kind"], row["pid"]
    local_host, local_port = split_address(row["local"])
    remote_host, _ = split_address(row["remote"])

    if kind == "Connected":
        remote_ip = _ip(remote_host)

        # Only report traffic leaving the local network; skip TIME_WAIT leftovers.
        if remote_ip is None or not remote_ip.is_global or pid == 0:
            return None

    if pid not in paths:
        paths[pid] = process_path(pid)

    path = paths[pid]
    name = names.get(pid) or (Path(path).name if path else f"PID {pid}")
    reasons = []
    risk = "SAFE"
    service = PORT_NAMES.get(local_port, "")
    scope = "Internet"

    if kind == "Listening":
        local_ip = _ip(local_host)

        if local_ip is not None and local_ip.is_loopback:
            scope = "This PC only"
        else:
            scope = "Local network"

            if local_port in RISKY_PORTS:
                reasons.append(
                    f"Port {local_port} ({service}) is open to your network."
                )
                risk = "WARNING"

    if any(part in path.lower() for part in RISKY_PARTS):
        reasons.append("Program runs from a temporary or user-writable folder.")
        risk = "WARNING"

    if name.lower() in SCRIPT_HOSTS:
        reasons.append(f"{name} is a script tool that is commonly abused.")
        risk = "WARNING"

    return {
        "kind": kind,
        "local": row["local"],
        "remote": row["remote"] if kind == "Connected" else "-",
        "pid": pid,
        "process": name,
        "path": path,
        "service": service,
        "scope": scope,
        "risk": risk,
        "reasons": reasons,
        "sha256": None,
    }


def _scan_file(path):
    """Returns (sha256, threat_risk_or_None, reasons)."""
    try:
        results = scan_path(path)
    except Exception as exc:
        return None, None, [f"Could not scan this program: {exc}"]

    sha, risk, reasons = None, None, []

    for result in results:
        sha = result.sha256

        if result.risk in ("HIGH", "CRITICAL"):
            risk = result.risk
            reasons.extend(result.reasons)

    return sha, risk, reasons


def run_network_check():
    names = process_names()
    paths = {}
    items = [
        item
        for row in read_connections()
        if (item := analyze(row, names, paths)) is not None
    ]

    verdicts = {}      # scan each program once, even if it has 40 connections

    for item in items:
        path = item["path"]

        if not path or not Path(path).is_file():
            continue

        if path not in verdicts:
            verdicts[path] = _scan_file(path)

        sha, risk, reasons = verdicts[path]
        item["sha256"] = sha

        if risk:
            item["risk"] = risk

        item["reasons"].extend(reasons)

    items.sort(key=lambda i: (SEVERITY.get(i["risk"], 3), i["kind"], i["process"].lower()))
    return items