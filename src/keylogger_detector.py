import os
import re
import csv
import json
import subprocess
from typing import List, Dict, Any

def _is_windows() -> bool:
    return os.name == 'nt'


def detect_process_keyloggers() -> List[Dict[str, Any]]:
    """Heuristic scan of running processes for suspicious names/window titles.

    Returns a list of dicts: {name, pid, session_name, mem_usage, window_title, reason}
    """
    findings: List[Dict[str, Any]] = []
    if not _is_windows():
        return findings

    try:
        out = subprocess.check_output(['tasklist', '/v', '/fo', 'csv'], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return findings

    # CSV header: "Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
    reader = csv.DictReader(out.splitlines())
    suspicious_patterns = re.compile(r'keylog|keylogger|klog|logger|keyboard|hook|kbd', re.IGNORECASE)

    for row in reader:
        name = row.get('Image Name') or row.get('ImageName') or ''
        pid = row.get('PID') or row.get('Pid') or ''
        win = row.get('Window Title') or row.get('WindowTitle') or ''
        mem = row.get('Mem Usage') or row.get('Memory') or ''
        reason = []
        if suspicious_patterns.search(name):
            reason.append('suspicious process name')
        if suspicious_patterns.search(win):
            reason.append('suspicious window title')
        if reason:
            findings.append({
                'name': name,
                'pid': pid,
                'mem': mem,
                'window_title': win,
                'reason': '; '.join(reason),
            })

    return findings


def detect_driver_keyloggers() -> List[Dict[str, Any]]:
    """Heuristic scan of installed drivers (kernel components) for suspicious names.

    Uses Windows `driverquery` output when available.
    """
    findings: List[Dict[str, Any]] = []
    if not _is_windows():
        return findings
    try:
        out = subprocess.check_output(['driverquery', '/v', '/fo', 'csv'], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return findings

    reader = csv.DictReader(out.splitlines())
    suspicious_patterns = re.compile(r'kbd|keyboard|filter|kbdclass|keylog|keylogger|hook', re.IGNORECASE)
    for row in reader:
        name = row.get('Module Name') or row.get('ModuleName') or row.get('Driver') or ''
        display = row.get('Display Name') or row.get('DisplayName') or ''
        path = row.get('Link Name') or row.get('Path') or ''
        if suspicious_patterns.search(name) or suspicious_patterns.search(display) or suspicious_patterns.search(path):
            findings.append({'name': name, 'display': display, 'path': path})
    return findings


def detect_registry_persistence() -> List[Dict[str, Any]]:
    """Check common Run registry keys for suspicious entries that may indicate persistence.

    Returns list of {hive, key, name, value}
    """
    findings: List[Dict[str, Any]] = []
    if not _is_windows():
        return findings
    try:
        import winreg
    except Exception:
        return findings

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ]
    suspicious_patterns = re.compile(r'keylog|keylogger|klog|logger|keyboard|hook', re.IGNORECASE)

    for hive, keypath in run_keys:
        try:
            with winreg.OpenKey(hive, keypath) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                        if suspicious_patterns.search(name) or suspicious_patterns.search(str(val)):
                            findings.append({'hive': str(hive), 'key': keypath, 'name': name, 'value': val})
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return findings


def detect_all() -> Dict[str, Any]:
    """Run all keylogger detection heuristics and return a structured report."""
    return {
        'platform': os.name,
        'process_findings': detect_process_keyloggers(),
        'driver_findings': detect_driver_keyloggers(),
        'registry_findings': detect_registry_persistence(),
    }


if __name__ == '__main__':
    import json
    print(json.dumps(detect_all(), indent=2))
