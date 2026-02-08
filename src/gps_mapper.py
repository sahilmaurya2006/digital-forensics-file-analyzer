import os
import csv
from typing import List, Dict, Any, Tuple, Optional

OUTPUT_CSV = os.path.join("reports", "gps_points.csv")


def _ensure_reports_dir() -> None:
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)


def create_gps_map(results: List[Dict[str, Any]]) -> Tuple[Optional[str], int]:
    """Collect GPS points from results and write a simple CSV. Returns (path, count)."""
    points = []
    for r in results:
        exif = r.get("exif") or {}
        lat = exif.get("GPS GPSLatitude")
        lon = exif.get("GPS GPSLongitude")
        if lat and lon:
            points.append({"filename": r.get("filename"), "lat": lat, "lon": lon, "path": r.get("path")})

    if not points:
        return None, 0

    try:
        _ensure_reports_dir()
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["filename", "path", "lat", "lon"])
            writer.writeheader()
            for p in points:
                writer.writerow({"filename": p["filename"], "path": p["path"], "lat": p["lat"], "lon": p["lon"]})
        return OUTPUT_CSV, len(points)
    except Exception:
        return None, 0
