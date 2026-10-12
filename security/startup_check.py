import os
import winreg
from pathlib import Path

from core.scanner import scan_path

RUN_KEYS = (
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Current user"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Current user (once)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "All users"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "All users (once)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "All users (32-bit)"),
)

# Folders that normal installed programs rarely start from.
RISKY_PARTS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
)

# Built-in tools that attackers like to abuse to run hidden commands.
SCRIPT_HOSTS = frozenset({
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe",
})

SEVERITY = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "SAFE": 3}


def _read_run_key(hive, subkey, location):
    items = []

    try:
        with winreg.OpenKey(hive, subkey) as key:
            index = 0

            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:             # no more values
                    break

                index += 1

                if isinstance(value, str) and value.strip():
                    items.append({
                        "name": name or "(Default)",
                        "command": value,
                        "location": f"Registry - {location}",
                    })

    except OSError:                         # key doesn't exist or isn't readable
        pass

    return items


def _startup_folders():
    folders = []
    start_menu = Path("Microsoft/Windows/Start Menu/Programs")

    for variable, label in (
        ("APPDATA", "Startup folder (user)"),
        ("PROGRAMDATA", "Startup folder (all users)"),
    ):
        base = os.environ.get(variable)

        if base:
            folders.append((Path(base) / start_menu / "Startup", label))

    return folders


def _read_startup_folder(folder, label):
    items = []

    try:
        for file in folder.iterdir():
            if file.is_file() and file.name.lower() != "desktop.ini":
                items.append({
                    "name": file.stem,
                    "command": str(file),
                    "location": label,
                })

    except OSError:
        pass

    return items


def collect_entries():
    entries = []

    for hive, subkey, location in RUN_KEYS:
        entries.extend(_read_run_key(hive, subkey, location))

    for folder, label in _startup_folders():
        entries.extend(_read_startup_folder(folder, label))

    return entries


def extract_executable(command):
    """Pull the program path out of a command line like '"C:\\x\\a.exe" --flag'."""
    command = os.path.expandvars(command.strip())

    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]

    # Unquoted paths can contain spaces, so try the longest guess first.
    parts = command.split(" ")

    for count in range(len(parts), 0, -1):
        candidate = " ".join(parts[:count])

        if Path(candidate).is_file():
            return candidate

    return parts[0]


def analyze(entry):
    exe = extract_executable(entry["command"])
    path = Path(exe)
    exists = path.is_file()
    reasons = []
    risk = "SAFE"

    if not exists:
        reasons.append("Target file was not found (a stale or broken entry).")
        risk = "WARNING"

    lowered = exe.lower()

    if any(part in lowered for part in RISKY_PARTS):
        reasons.append("Starts from a temporary or user-writable folder.")
        risk = "WARNING"

    name = path.name.lower()

    if "." not in name:
        name += ".exe"

    if name in SCRIPT_HOSTS:
        reasons.append(
            f"Runs through {name}, a tool commonly abused to hide commands."
        )
        risk = "WARNING"

    return {
        **entry,
        "path": exe,
        "exists": exists,
        "risk": risk,
        "reasons": reasons,
        "sha256": None,
    }


def _scan_item(item):
    try:
        results = scan_path(item["path"])

    except Exception as exc:
        item["reasons"].append(f"Could not scan this file: {exc}")
        return

    for result in results:
        item["sha256"] = result.sha256

        if result.risk in ("HIGH", "CRITICAL"):
            item["risk"] = result.risk
            item["reasons"].extend(result.reasons)


def run_startup_check():
    items = [analyze(entry) for entry in collect_entries()]

    for item in items:
        if item["exists"]:
            _scan_item(item)

    items.sort(key=lambda item: (SEVERITY.get(item["risk"], 3), item["name"].lower()))
    return items