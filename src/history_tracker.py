import os
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

HISTORY_FILE = os.path.join("reports", "last_scan.json")


def _ensure_reports_dir() -> None:
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)


def save_scan(results: List[Dict[str, Any]]) -> Optional[str]:
    """Save a minimal snapshot of the last scan to reports/last_scan.json."""
    try:
        _ensure_reports_dir()
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "results": results,
        }
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return HISTORY_FILE
    except Exception:
        return None


def compare_scans(results: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, List[str]]], Optional[str]]:
    """Compare the given results with the previous scan.

    Returns (changes, error_message). changes is a dict with lists for 'added', 'deleted', 'modified'.
    """
    if not os.path.exists(HISTORY_FILE):
        return None, "No previous scan found."

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            prev = json.load(f)
        prev_results = prev.get("results", [])

        prev_map = {r.get("path"): r.get("sha256") for r in prev_results}
        new_map = {r.get("path"): r.get("sha256") for r in results}

        added = [p for p in new_map.keys() if p not in prev_map]
        deleted = [p for p in prev_map.keys() if p not in new_map]
        modified = [p for p in new_map.keys() if p in prev_map and prev_map.get(p) != new_map.get(p)]

        changes = {"added": added, "deleted": deleted, "modified": modified}
        return changes, None
    except Exception as e:
        return None, str(e)
