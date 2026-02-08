import re
import os
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("dffa.usb_devices")

# Patterns to detect USB device IDs and descriptive names
VID_PID_RE = re.compile(r'(VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\s,;\)]*)')
USB_KEYWORD_RE = re.compile(r'\b(USB|removable|plug|device|arrival|connected|hub)\b', re.IGNORECASE)
INSTANCE_ID_RE = re.compile(r'([^\\\s]+\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\s,;]*)', re.IGNORECASE)


def _scan_text_for_devices(path: str) -> List[Dict[str, Any]]:
    """Scan a plain-text event-log export for USB device attach messages.

    Returns list of records with keys: timestamp (if found), device_id, message
    """
    results: List[Dict[str, Any]] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if not USB_KEYWORD_RE.search(line):
                    continue
                # try find VID/PID or instance id
                vid = None
                m = VID_PID_RE.search(line)
                if m:
                    vid = m.group(1)
                else:
                    m2 = INSTANCE_ID_RE.search(line)
                    if m2:
                        vid = m2.group(1)
                # try find a timestamp at line start e.g. 2025-11-11 10:00:00 or similar
                ts = None
                ts_match = re.match(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
                if ts_match:
                    ts = ts_match.group(1)
                results.append({
                    'timestamp': ts,
                    'device_id': vid,
                    'message': line.strip()
                })
    except Exception as e:
        logger.debug("Failed to read text log %s: %s", path, e)
    return results


def find_usb_device_events(log_names: Optional[List[str]] = None, max_events: Optional[int] = None, evtx_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Find USB device connect/disconnect events.

    Tries to use win32evtlog when available; if not, or if an evtx_path is provided,
    falls back to scanning the provided text export.
    """
    # prefer live reading if pywin32 is available
    try:
        import win32evtlog
    except Exception:
        win32evtlog = None

    results: List[Dict[str, Any]] = []

    # If live API is available, attempt to read System or Setup logs
    if win32evtlog and not evtx_path:
        server = 'localhost'
        logs = log_names or ['System', 'Setup']
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        for log_name in logs:
            try:
                hand = win32evtlog.OpenEventLog(server, log_name)
            except Exception as e:
                logger.debug("Failed to open log %s: %s", log_name, e)
                continue
            read_count = 0
            while True:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                except Exception:
                    break
                if not events:
                    break
                for evt in events:
                    if max_events and read_count >= max_events:
                        break
                    read_count += 1
                    inserts = getattr(evt, 'StringInserts', None)
                    time_generated = getattr(evt, 'TimeGenerated', None)
                    tstr = None
                    try:
                        tstr = time_generated.Format() if time_generated else None
                    except Exception:
                        try:
                            tstr = str(time_generated)
                        except Exception:
                            tstr = None
                    text_payload = ''
                    if inserts:
                        try:
                            text_payload = '\n'.join([s for s in inserts if isinstance(s, str)])
                        except Exception:
                            text_payload = str(inserts)
                    else:
                        try:
                            text_payload = str(evt)
                        except Exception:
                            text_payload = ''
                    if not USB_KEYWORD_RE.search(text_payload):
                        continue
                    # extract device id
                    vid = None
                    m = VID_PID_RE.search(text_payload)
                    if m:
                        vid = m.group(1)
                    else:
                        m2 = INSTANCE_ID_RE.search(text_payload)
                        if m2:
                            vid = m2.group(1)

                    results.append({'timestamp': tstr, 'device_id': vid, 'message': text_payload, 'log_name': log_name})
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass
        return results

    # Fallback: if evtx_path provided, scan text
    if evtx_path and os.path.exists(evtx_path):
        return _scan_text_for_devices(evtx_path)

    # If no live API and no file, nothing to do
    logger.info("No pywin32 available and no evtx_path provided for USB device events")
    return []


def save_results(results: List[Dict[str, Any]], output_dir: str = 'reports', base_name: str = 'usb_devices') -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    jpath = os.path.join(output_dir, base_name + '.json')
    cpath = os.path.join(output_dir, base_name + '.csv')
    try:
        with open(jpath, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
    except Exception:
        logger.exception('Failed to write json')
    # write CSV
    try:
        import csv
        keys = []
        for r in results:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        with open(cpath, 'w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            for r in results:
                row = {}
                for k in keys:
                    v = r.get(k, '')
                    if isinstance(v, (list, dict)):
                        row[k] = json.dumps(v, ensure_ascii=False)
                    else:
                        row[k] = v
                w.writerow(row)
    except Exception:
        logger.exception('Failed to write csv')
    return {'json': jpath, 'csv': cpath}
