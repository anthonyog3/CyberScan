import json
import math
from collections import Counter
from pathlib import Path

from utils.paths import resource_path

DOUBLE_EXTENSIONS = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
    ".jpg.exe", ".png.exe", ".txt.exe", ".zip.exe"
}

SUSPICIOUS_EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"
}

# Extensions people trust to be harmless documents or media.
# A Windows program hiding under one of these is suspicious.
HARMLESS_EXTENSIONS = {
    ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav",
}

HEADER_BYTES = 4096                    # enough to reach the PE header
ENTROPY_SAMPLE_BYTES = 1024 * 1024     # only the first 1 MB is measured
ENTROPY_MIN_SIZE = 20 * 1024           # tiny samples give meaningless numbers
ENTROPY_THRESHOLD = 7.2                # out of 8.0; packed programs score higher

RTL_OVERRIDE = "\u202e"                # Unicode "right-to-left override"


def load_hash_database(path=resource_path("database/hashes.json")) -> set[str]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return {value.lower() for value in data.get("malicious_sha256", [])}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def is_pe(header: bytes) -> bool:
    """True if the bytes start like a Windows program (.exe, .dll, .scr...).

    A program starts with 'MZ'. Bytes 0x3C-0x3F then say where the real
    'PE' header sits, and we check that it is really there. Checking only
    'MZ' would also match a text file that begins with someone's initials.
    """
    if len(header) < 0x40 or not header.startswith(b"MZ"):
        return False

    offset = int.from_bytes(header[0x3C:0x40], "little")
    return header[offset:offset + 4] == b"PE\x00\x00"


def shannon_entropy(data: bytes) -> float:
    """Randomness from 0.0 (every byte identical) to 8.0 (perfectly random)."""
    if not data:
        return 0.0

    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )


def content_checks(path: Path) -> list[str]:
    """Checks that look at what is INSIDE the file, not what it is called."""
    reasons = []

    try:
        with open(path, "rb") as file:
            header = file.read(HEADER_BYTES)

            if not is_pe(header):
                return reasons

            sample = header + file.read(ENTROPY_SAMPLE_BYTES - len(header))

    except OSError:
        return reasons

    extension = path.suffix.lower()

    if extension in HARMLESS_EXTENSIONS:
        reasons.append(
            f"File is a Windows program disguised as a '{extension}' file."
        )

    if len(sample) >= ENTROPY_MIN_SIZE:
        entropy = shannon_entropy(sample)

        if entropy >= ENTROPY_THRESHOLD:
            reasons.append(
                f"High entropy ({entropy:.1f}/8): the program may be "
                "packed or encrypted."
            )

    return reasons


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

    if RTL_OVERRIDE in p.name:
        reasons.append(
            "Filename contains a right-to-left override character, "
            "used to fake file extensions."
        )

    reasons.extend(content_checks(p))

    return reasons
