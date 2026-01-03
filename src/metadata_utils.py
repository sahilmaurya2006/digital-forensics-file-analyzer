import os
import hashlib
from datetime import datetime
import exifread
from typing import Dict
try:
    from PIL import Image
except Exception:
    Image = None

def calculate_hashes(file_path, chunk_size=8192):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception as e:
        return None, None


def get_file_basic_metadata(file_path):
    try:
        stats = os.stat(file_path)
        return {
            "filename": os.path.basename(file_path),
            "path": os.path.abspath(file_path),
            "size_bytes": stats.st_size,
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
        }
    except Exception as e:
        return None

def extract_exif(file_path):
    # Returns dict of useful EXIF tags if image
    try:
        # Try exifread first (good for JPEG/TIFF)
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            exif: Dict[str, str] = {}
            for tag in tags:
                if tag in ('Image Make', 'Image Model', 'EXIF DateTimeOriginal', 'GPS GPSLatitude', 'GPS GPSLongitude'):
                    exif[tag] = str(tags[tag])
            # If we found tags, return them
            if exif:
                return exif

        # Fallback: for PNG or images where exifread found nothing, try Pillow's info dictionary
        if Image is not None:
            try:
                img = Image.open(file_path)
                info = getattr(img, 'info', {}) or {}
                # Map some common keys to a simple exif-like dict
                png_exif: Dict[str, str] = {}
                for k in ('Software', 'Author', 'Description', 'date:create', 'date:modify'):
                    if k in info:
                        png_exif[k] = str(info[k])
                # Some PNGs may include textual chunks under 'text'
                text = info.get('text') or info.get('Text')
                if text:
                    if isinstance(text, dict):
                        for tk, tv in text.items():
                            png_exif[f'text:{tk}'] = str(tv)
                    else:
                        png_exif['text'] = str(text)
                if png_exif:
                    return png_exif
            except Exception:
                pass

        return {}
    except Exception:
        return {}
