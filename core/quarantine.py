import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path

QUARANTINE_DIR = Path("quarantine")
METADATA_FILE = QUARANTINE_DIR / "metadata.json"


def _load_metadata():
    QUARANTINE_DIR.mkdir(exist_ok=True)
    if not METADATA_FILE.exists():
        return {}
    try:
        return json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_metadata(data):
    QUARANTINE_DIR.mkdir(exist_ok=True)
    METADATA_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def quarantine_file(path: str, sha256: str | None = None) -> str:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(path)

    qid = uuid.uuid4().hex
    destination = QUARANTINE_DIR / qid
    QUARANTINE_DIR.mkdir(exist_ok=True)
    shutil.move(str(source), str(destination))

    metadata = _load_metadata()
    metadata[qid] = {
        "name": source.name,
        "original_path": str(source.resolve()),
        "stored_path": str(destination.resolve()),
        "sha256": sha256,
        "quarantined_at": datetime.now().isoformat(timespec="seconds"),
    }
    _save_metadata(metadata)
    return qid


def list_quarantined():
    return _load_metadata()


def restore_file(qid: str, overwrite: bool = False) -> str:
    metadata = _load_metadata()
    if qid not in metadata:
        raise KeyError(qid)

    original = Path(metadata[qid]["original_path"])
    stored = QUARANTINE_DIR / qid  # rebuilt from the ID, not the saved absolute path

    if not stored.exists():
        raise FileNotFoundError(str(stored))

    if original.exists():
        if not overwrite:
            raise FileExistsError(str(original))
        original.unlink()

    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(original))
    del metadata[qid]
    _save_metadata(metadata)
    return str(original)


def delete_quarantined(qid: str) -> None:
    metadata = _load_metadata()
    if qid not in metadata:
        raise KeyError(qid)

    (QUARANTINE_DIR / qid).unlink(missing_ok=True)
    del metadata[qid]
    _save_metadata(metadata)