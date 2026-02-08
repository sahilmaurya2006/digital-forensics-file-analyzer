import os
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("dffa.win_artifacts")

# Try optional imports
try:
    import win32file
except Exception:
    win32file = None

try:
    from win32com.client import Dispatch
except Exception:
    Dispatch = None


def _ts(path: str) -> str:
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
    except Exception:
        return ""


def get_prefetch_info(prefetch_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return a list of prefetch file summaries (exe name, filename, modified).

    Prefetch parsing is non-trivial; this function provides a lightweight
    summary by listing .pf files and extracting the exe name from the
    filename (before the first '-').
    """
    if not prefetch_dir:
        prefetch_dir = r"C:\Windows\Prefetch"
    prefetch_dir = os.path.abspath(prefetch_dir)
    out = []
    if not os.path.isdir(prefetch_dir):
        logger.debug("Prefetch directory not found: %s", prefetch_dir)
        return out

    try:
        entries = os.listdir(prefetch_dir)
    except Exception as e:
        logger.debug("Cannot list prefetch directory %s: %s", prefetch_dir, e)
        return out

    for fname in entries:
        if not fname.lower().endswith('.pf'):
            continue
        path = os.path.join(prefetch_dir, fname)
        exe = fname.split('-', 1)[0] if '-' in fname else fname
        out.append({
            'filename': fname,
            'exe': exe,
            'path': path,
            'modified': _ts(path),
        })
    return out


def get_recent_files(recent_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return list of recent items. Attempts to resolve .lnk targets if possible."""
    if not recent_dir:
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~\\AppData\\Roaming')
        recent_dir = os.path.join(appdata, r"Microsoft\Windows\Recent")
    recent_dir = os.path.abspath(recent_dir)
    out = []
    if not os.path.isdir(recent_dir):
        logger.debug("Recent directory not found: %s", recent_dir)
        return out

    resolver = None
    if Dispatch:
        try:
            shell = Dispatch("WScript.Shell")
            resolver = shell
        except Exception:
            resolver = None

    for fname in os.listdir(recent_dir):
        path = os.path.join(recent_dir, fname)
        try:
            mtime = _ts(path)
        except Exception:
            mtime = ''
        target = None
        if resolver and fname.lower().endswith('.lnk'):
            try:
                shortcut = resolver.CreateShortcut(path)
                target = shortcut.TargetPath
            except Exception:
                target = None
        out.append({
            'filename': fname,
            'path': path,
            'target': target,
            'modified': mtime,
        })
    return out


def get_drive_info(drive_letters: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Return info for drive letters: drive, exists, type (if win32file available).

    Drive type constants: win32file.GetDriveType returns integers; if not
    available, type will be 'unknown'.
    """
    if not drive_letters:
        # common removable letters
        drive_letters = ['E:', 'F:', 'G:', 'H:']
    out = []
    for d in drive_letters:
        dnorm = d.strip()
        if len(dnorm) == 1:
            dnorm = dnorm + ':'
        root = dnorm + '\\'
        exists = os.path.exists(root)
        dtype = 'unknown'
        is_removable = None
        if win32file:
            try:
                t = win32file.GetDriveType(root)
                # constants: 2 == DRIVE_REMOVABLE
                is_removable = (t == 2)
                dtype = str(t)
            except Exception:
                dtype = 'error'
        out.append({'drive': dnorm, 'root': root, 'exists': exists, 'drive_type': dtype, 'is_removable': is_removable})
    return out


def gather_all(prefetch_dir: Optional[str] = None, recent_dir: Optional[str] = None, drive_letters: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        'prefetch': get_prefetch_info(prefetch_dir=prefetch_dir),
        'recent': get_recent_files(recent_dir=recent_dir),
        'drives': get_drive_info(drive_letters=drive_letters),
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefetch', help='Prefetch dir')
    parser.add_argument('--recent', help='Recent dir')
    parser.add_argument('--drives', help='Comma-separated drives')
    args = parser.parse_args()
    drives = [d.strip() for d in args.drives.split(',')] if args.drives else None
    out = gather_all(prefetch_dir=args.prefetch, recent_dir=args.recent, drive_letters=drives)
    print(json.dumps(out, indent=2))
