import os
import sys
from pathlib import Path

APP_NAME = "CyberScan"


def resource_path(relative: str) -> Path:
    """Read-only files shipped inside the app (e.g. database/hashes.json)."""
    base = getattr(sys, "_MEIPASS", None)       # set by PyInstaller when packaged
    root = Path(base) if base else Path(__file__).resolve().parent.parent
    return root / relative


def data_dir() -> Path:
    """Writable folder for history, settings, quarantine, and logs."""
    if getattr(sys, "frozen", False):
        root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    else:
        root = Path(__file__).resolve().parent.parent   # your project folder

    root.mkdir(parents=True, exist_ok=True)
    return root