import hashlib
from pathlib import Path

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 hash of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        while chunk := file.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
