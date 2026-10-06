from pathlib import Path
import json

DOUBLE_EXTENSIONS = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
    ".jpg.exe", ".png.exe", ".txt.exe", ".zip.exe"
}

SUSPICIOUS_EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"
}

def load_hash_database(path: str = "database/hashes.json") -> set[str]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return {value.lower() for value in data.get("malicious_sha256", [])}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def static_checks(path: str) -> list[str]:
    """Perform non-executing heuristic checks."""
    p = Path(path)
    name = p.name.lower()
    suffixes = "".join(p.suffixes).lower()
    reasons = []

    if any(suffixes.endswith(ext) for ext in DOUBLE_EXTENSIONS):
        reasons.append("Double file extension commonly used to disguise executables.")

    if p.suffix.lower() in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
        reasons.append(f"Executable/script file type detected: {p.suffix.lower()}.")

    suspicious_names = {"keygen", "crack", "patcher", "loader"}
    if p.stem.lower() in suspicious_names:
        reasons.append("Filename matches a generic high-risk software naming pattern.")

    if name.startswith("invoice") and p.suffix.lower() in {".exe", ".scr", ".bat", ".cmd"}:
        reasons.append("Executable uses a filename commonly associated with documents.")

    return reasons
