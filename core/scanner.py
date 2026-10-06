from dataclasses import dataclass
from pathlib import Path
import time

from core.hasher import sha256_file
from core.detector import load_hash_database, static_checks
from core.risk_engine import calculate_risk


@dataclass
class ScanResult:
    path: str
    sha256: str | None
    risk: str
    score: int
    reasons: list[str]
    error: str | None = None


SKIP_EXTENSIONS = {".tmp", ".log", ".iso", ".dll"}


def scan_path(target: str, hash_db_path="database/hashes.json", callback=None):
    root = Path(target)

    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    paths = [root] if root.is_file() else [
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() not in SKIP_EXTENSIONS
    ]

    hashes = load_hash_database(hash_db_path)
    results = []
    total = len(paths)

    for index, path in enumerate(paths, 1):
        try:
            digest = sha256_file(str(path))
            reasons = static_checks(str(path))
            match = digest.lower() in hashes

            if match:
                reasons.insert(0, "Exact SHA-256 match found in local detection database.")

            risk, score = calculate_risk(match, reasons)
            result = ScanResult(str(path), digest, risk, score, reasons)

        except (PermissionError, OSError) as exc:
            result = ScanResult(str(path), None, "UNKNOWN", 0, [], str(exc))

        results.append(result)

        if callback:
            callback(index, total, str(path), result)

    if callback:
        callback("done", total, None, None)

    return results