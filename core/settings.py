import json
from pathlib import Path

SETTINGS_FILE = Path("database/settings.json")

DEFAULTS = {
    "realtime_enabled": False,
    "protected_folders": None, # None = never configured (app picks Downloads)
}


def load_settings():
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}

    return {**DEFAULTS, **data}

def save_settings(settings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")        