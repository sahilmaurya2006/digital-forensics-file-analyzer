import os
from datetime import datetime
from typing import Dict, Any, Tuple, List

__all__ = ["get_suspicion_score"]


def get_suspicion_score(file_metadata: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Heuristic suspicion scoring for a file.

    Returns (score 0-100, list_of_reasons).
    """
    score = 0
    reasons: List[str] = []

    filename = file_metadata.get("filename", "")
    ext = os.path.splitext(filename)[1].lower()
    size = file_metadata.get("size_bytes", 0)
    created = file_metadata.get("created", "")

    # Extension-based heuristics
    suspicious_exts = [".exe", ".bat", ".scr", ".vbs"]
    if ext in suspicious_exts:
        score += 30
        reasons.append("Executable file")

    # Hidden or temporary filenames
    if filename.startswith('.') or filename.startswith('~'):
        score += 20
        reasons.append("Hidden filename")

    # Odd creation times (early morning)
    try:
        ctime = datetime.fromisoformat(created)
        if 0 <= ctime.hour <= 4:
            score += 15
            reasons.append("Created at odd hour")
    except Exception:
        pass

    # Very small or very large files
    if size < 50 or size > 100_000_000:  # 100 MB
        score += 10
        reasons.append("Unusual file size")

    # Multiple dots in filename (could be disguised extension)
    if "." in filename and filename.count('.') > 1:
        score += 25
        reasons.append("Multiple dots in filename")

    # 6️⃣ Magic/header mismatch: check file signature vs extension
    path = file_metadata.get("path")
    try:
        sig = _read_magic(path, 16)
        magic_type = _identify_magic(sig)
        if magic_type:
            # if magic indicates executable or archive but extension is misleading
            if magic_type == 'exe' and ext != '.exe':
                score += 40
                reasons.append(f"File content is executable (magic: {magic_type}) but extension is {ext}")
            # mismatched type (e.g., .pdf but magic not pdf)
            if ext in ('.pdf',) and magic_type != 'pdf':
                score += 20
                reasons.append(f"Extension {ext} does not match file signature ({magic_type})")
    except Exception:
        # if we can't read the file, don't escalate — other checks still apply
        pass

    # 7️⃣ High entropy (possible packed/encrypted data)
    try:
        ent = _sample_entropy(path)
        if ent and ent > 7.5:
            score += 30
            reasons.append(f"High entropy ({ent:.2f}) — possible packed/encrypted content")
    except Exception:
        pass

    return min(score, 100), reasons


def _read_magic(path: str, n: int = 16) -> bytes:
    """Read up to n bytes from file start for signature detection."""
    if not path:
        return b''
    try:
        with open(path, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''


def _identify_magic(sig: bytes) -> str:
    """Identify a small set of common file signatures. Returns short type key or empty string."""
    if not sig:
        return ''
    s = sig
    if s.startswith(b'%PDF'):
        return 'pdf'
    if s.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if s.startswith(b'\xff\xd8'):
        return 'jpg'
    if s.startswith(b'PK'):
        return 'zip'
    if s.startswith(b'MZ'):
        return 'exe'
    if s.startswith(b'\x7fELF'):
        return 'elf'
    return ''


def _sample_entropy(path: str, sample_size: int = 4096) -> float:
    """Compute Shannon entropy on a sample of the file (first sample_size bytes)."""
    import math
    if not path:
        return 0.0
    try:
        with open(path, 'rb') as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        ent = 0.0
        length = len(data)
        for v in freq.values():
            p = v / length
            ent -= p * math.log2(p)
        return ent
    except Exception:
        return 0.0
