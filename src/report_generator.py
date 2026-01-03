import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def save_to_csv(results: List[Dict[str, Any]], output_dir: str = "reports", output_file: Optional[str] = None) -> str:
    """Save results to CSV. Ensures deterministic column order for readability."""
    _ensure_dir(output_dir)
    if not results:
        return ""
    if not output_file:
        output_file = os.path.join(output_dir, "report.csv")
    # Determine a friendly field order
    preferred = ["filename", "path", "size_bytes", "created", "modified", "md5", "sha256", "exif"]
    all_keys = list(results[0].keys())
    # put preferred keys first if present, then any remaining keys
    ordered = [k for k in preferred if k in all_keys] + [k for k in all_keys if k not in preferred]
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered)
        writer.writeheader()
        writer.writerows(results)
    return output_file


def save_to_json(results: List[Dict[str, Any]], output_dir: str = "reports", output_file: Optional[str] = None) -> str:
    """Save results to JSON and wrap with metadata (generated_at, version)."""
    _ensure_dir(output_dir)
    if not output_file:
        output_file = os.path.join(output_dir, "report.json")
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "tool": "digital-forensics-file-analyzer",
        "version": "1.0",
        "count": len(results),
        "results": results,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
    return output_file


def save_to_pdf(results: List[Dict[str, Any]], output_dir: str = "reports", output_file: Optional[str] = None) -> str:
    """Create a simple multi-page PDF report summarizing each file in a readable layout."""
    _ensure_dir(output_dir)
    if not output_file:
        output_file = os.path.join(output_dir, "report.pdf")
    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter

    # Title page
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width / 2, height - 100, "Digital Forensics - File Analyzer")
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, height - 120, f"Generated: {datetime.utcnow().isoformat()}Z")
    c.showPage()

    # Content
    for entry in results:
        y = height - 40
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, f"File: {entry.get('filename')}")
        y -= 18
        c.setFont("Helvetica", 9)
        c.drawString(40, y, f"Path: {entry.get('path')}")
        y -= 14
        c.drawString(40, y, f"Size (bytes): {entry.get('size_bytes')}")
        y -= 14
        c.drawString(40, y, f"Created: {entry.get('created')}")
        y -= 14
        c.drawString(40, y, f"Modified: {entry.get('modified')}")
        y -= 14
        c.drawString(40, y, f"MD5: {entry.get('md5')}")
        y -= 12
        # For layout, show first 16 chars of sha256
        sha = entry.get('sha256') or ""
        c.drawString(40, y, f"SHA256 (prefix): {sha[:16]}")
        y -= 14
        exif = entry.get('exif') or {}
        if exif:
            c.drawString(40, y, "EXIF:")
            y -= 12
            for k, v in exif.items():
                if y < 80:
                    c.showPage()
                    y = height - 40
                c.drawString(60, y, f"{k}: {v}")
                y -= 12
        c.showPage()

    c.save()
    return output_file
