from pathlib import Path
import json
import shutil
import uuid

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
    shutil.move(str(source), str(destination))

    metadata = _load_metadata()
    metadata[qid] = {
        "original_path": str(source.resolve()),
        "stored_path": str(destination.resolve()),
        "sha256": sha256
    }
    _save_metadata(metadata)
    return qid

def list_quarantined():
    return _load_metadata()

def restore_file(qid: str) -> str:
    metadata = _load_metadata()
    if qid not in metadata:
        raise KeyError(qid)

    item = metadata[qid]
    stored = Path(item["stored_path"])
    original = Path(item["original_path"])

    if not stored.exists():
        raise FileNotFoundError(str(stored))

    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(original))
    del metadata[qid]
    _save_metadata(metadata)
    return str(original)
