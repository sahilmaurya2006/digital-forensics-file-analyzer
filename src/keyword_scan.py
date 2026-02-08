import os
from typing import List


def scan_keywords(file_path: str, keywords: List[str] = None) -> List[str]:
    """Simple keyword scanner for text-based files.

    Returns a list of unique keywords found in the file. Quiet fallback if file can't be read.
    """
    if keywords is None:
        keywords = [
            "password",
            "passwd",
            "secret",
            "apikey",
            "api_key",
            "ssn",
            "credit",
            "confidential",
        ]

    _, ext = os.path.splitext(file_path)
    # only operate on likely-text files
    if ext.lower() not in (".txt", ".csv", ".log", ".cfg", ".json"):
        return []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read().lower()
    except Exception:
        return []

    found = []
    for kw in keywords:
        if kw.lower() in data:
            found.append(kw)
    return found
