import re
import logging
import json
import os
from typing import List, Dict, Any, Optional

# optional import for hashing
try:
    from src.metadata_utils import calculate_hashes
except Exception:
    calculate_hashes = None

logger = logging.getLogger("dffa.usb_audit")


def _normalize_drives(drives: Optional[List[str]]) -> List[str]:
    if not drives:
        return ["E:", "F:", "G:"]
    normalized = []
    for d in drives:
        d = d.strip()
        if not d:
            continue
        # Accept 'E' or 'E:' or 'E:\\' forms
        if len(d) == 1 and d.isalpha():
            d = d.upper() + ':'
        if d.endswith('\\'):
            d = d[:-1]
        normalized.append(d.upper())
    return normalized


def analyze_usb_file_access(drive_letters: Optional[List[str]] = None, log_names: Optional[List[str]] = None, max_events: Optional[int] = None, evtx_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan Windows Event Logs for file accesses on removable drive letters.

    Returns a list of records with keys: drive, event_id, time_generated, message, log_name

    This function requires pywin32 (win32evtlog). If it's not available or the
    platform isn't Windows, the function will return an empty list and log a warning.
    """
    try:
        import win32evtlog
    except Exception as e:
        logger.warning("pywin32 (win32evtlog) not available or not running on Windows: %s", e)
        # Fallback: if an exported event-log/text file path is provided, try to parse it
        if evtx_path and isinstance(evtx_path, str):
            try:
                return _scan_text_evtx(evtx_path, drive_letters)
            except Exception as ex:
                logger.debug("Failed to parse evtx/text fallback %s: %s", evtx_path, ex)
        return []

    drives = _normalize_drives(drive_letters)
    logs = log_names or ["Security"]

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    server = 'localhost'

    pattern = re.compile(r'([A-Z]:\\[^\r\n]+\.(txt|jpg|jpeg|pdf|exe|docx|xlsx|png|mp4|zip))', re.IGNORECASE)

    results: List[Dict[str, Any]] = []

    for log_name in logs:
        try:
            hand = win32evtlog.OpenEventLog(server, log_name)
        except Exception as e:
            logger.debug("Failed to open log %s: %s", log_name, e)
            # If the caller provided an exported event log / text fallback, try parsing it
            # when we cannot open the live Event Log (for example due to privileges).
            if evtx_path and isinstance(evtx_path, str) and os.path.exists(evtx_path):
                try:
                    logger.info("Falling back to parsing provided evtx/text file: %s", evtx_path)
                    fb_results = _scan_text_evtx(evtx_path, drive_letters)
                    results.extend(fb_results)
                except Exception:
                    logger.debug("Fallback parse failed for %s", evtx_path)
            # If this appears to be a privilege error, give a clearer hint to the user.
            try:
                msg = str(e)
                if '1314' in msg or 'A required privilege' in msg or 'privilege' in msg.lower():
                    logger.warning(
                        "Insufficient privileges to open Event Log '%s' (error: %s). "
                        "Try running the tool from an elevated prompt (Run as Administrator) to read Security logs.",
                        log_name, e
                    )
            except Exception:
                pass
            continue

        read_count = 0
        while True:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception as err:
                logger.debug("ReadEventLog failed for %s: %s", log_name, err)
                # If reading the live Event Log fails (often due to privileges),
                # try parsing the provided exported event-log/text file once so
                # non-elevated users can still analyze USB-related events.
                if evtx_path and isinstance(evtx_path, str) and os.path.exists(evtx_path):
                    try:
                        logger.info("ReadEventLog failed; falling back to parsing provided evtx/text file: %s", evtx_path)
                        fb_results = _scan_text_evtx(evtx_path, drive_letters)
                        results.extend(fb_results)
                    except Exception:
                        logger.debug("Fallback parse failed for %s", evtx_path)
                break
            if not events:
                break
            for event in events:
                # Respect an optional max_events limit
                if max_events and read_count >= max_events:
                    break
                read_count += 1
                try:
                    inserts = getattr(event, 'StringInserts', None)
                    if not inserts:
                        continue
                    for text in inserts:
                        if not isinstance(text, str):
                            continue
                        # quick drive check
                        if not any(d in text.upper() for d in drives):
                            continue
                        m = pattern.search(text)
                        if m:
                            # EventID can be a masked integer; keep raw
                            event_id = getattr(event, 'EventID', None)
                            tgen = getattr(event, 'TimeGenerated', None)
                            try:
                                tstr = tgen.Format() if tgen else ''
                            except Exception:
                                try:
                                    tstr = str(tgen)
                                except Exception:
                                    tstr = ''
                            results.append({
                                'drive': m.group(1)[:2],
                                'event_id': int(event_id) if event_id is not None else None,
                                'time_generated': tstr,
                                'message': text,
                                'log_name': log_name,
                            })
                except Exception:
                    # ignore parse errors for robustness
                    continue
            if max_events and read_count >= max_events:
                break
        try:
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    return results


def annotate_usb_activity_with_hashes(activity: List[Dict[str, Any]], history_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Annotate usb activity records with before/after hashes and status.

    For each activity record that contains a file path in `message`, compute the
    current SHA256 (after_hash) if the file exists. If a history_path is
    provided or a default `reports/last_scan.json` exists, try to load the
    previous sha256 (before_hash) for that path. Set record['before_hash'],
    record['after_hash'], and record['status'] where status is one of:
      - 'unchanged' (hashes match)
      - 'modified' (hashes differ)
      - 'new' (no previous hash)
      - 'missing' (file not accessible now)
    """
    # load previous snapshot if available
    prev_map = {}
    try:
        if history_path and isinstance(history_path, str) and history_path != '':
            with open(history_path, 'r', encoding='utf-8') as f:
                payload = json.load(f)
                for r in payload.get('results', []):
                    p = r.get('path')
                    h = r.get('sha256')
                    if p and h:
                        # normalize previous path keys for reliable matching
                        pk = os.path.normcase(os.path.normpath(p))
                        prev_map[pk] = h
        else:
            # try default location
            default = os.path.join('reports', 'last_scan.json')
            if os.path.exists(default):
                with open(default, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                    for r in payload.get('results', []):
                        p = r.get('path')
                        h = r.get('sha256')
                        if p and h:
                            pk = os.path.normcase(os.path.normpath(p))
                            prev_map[pk] = h
    except Exception:
        prev_map = {}

    # annotate
    for rec in activity:
        rec['before_hash'] = None
        rec['after_hash'] = None
        rec['status'] = None
        # try to extract a path from message using regex
        msg = rec.get('message', '')
        m = re.search(r'([A-Z]:\\[^\r\n]+)', msg, re.IGNORECASE)
        file_path = m.group(1) if m else None
        if not file_path:
            rec['status'] = 'unknown'
            continue
        # normalize path for matching
        file_path_norm = os.path.normcase(os.path.normpath(file_path))
        # before_hash from prev_map
        rec['before_hash'] = prev_map.get(file_path_norm)
        # compute current hash if possible
        actual_path = os.path.normpath(file_path)
        if os.path.exists(actual_path) and os.path.isfile(actual_path):
            if calculate_hashes:
                try:
                    _, sha256 = calculate_hashes(actual_path)
                    rec['after_hash'] = sha256
                except Exception:
                    rec['after_hash'] = None
            else:
                rec['after_hash'] = None
        else:
            rec['after_hash'] = None

        # determine status
        if rec['after_hash'] is None and rec['before_hash'] is None:
            rec['status'] = 'missing'
        elif rec['before_hash'] is None and rec['after_hash']:
            rec['status'] = 'new'
        elif rec['before_hash'] and rec['after_hash']:
            if rec['before_hash'] == rec['after_hash']:
                rec['status'] = 'unchanged'
            else:
                rec['status'] = 'modified'
        else:
            rec['status'] = 'unknown'

    return activity


def _scan_text_evtx(path: str, drive_letters: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Very small fallback parser that scans a plain-text export of event logs
    for file-paths on the drives of interest.

    This keeps the tool usable when pywin32 is not installed and a human-exported
    log or plain text dump is available.
    """
    drives = _normalize_drives(drive_letters)
    pattern = re.compile(r'([A-Z]:\\[^\r\n]+\.(txt|jpg|jpeg|pdf|exe|docx|xlsx|png|mp4|zip))', re.IGNORECASE)
    results: List[Dict[str, Any]] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if not any(d in line.upper() for d in drives):
                    continue
                m = pattern.search(line)
                if m:
                    results.append({
                        'drive': m.group(1)[:2],
                        'event_id': None,
                        'time_generated': '',
                        'message': line.strip(),
                        'log_name': os.path.basename(path),
                    })
    except Exception as e:
        logger.debug("Failed to read fallback file %s: %s", path, e)
    return results


if __name__ == "__main__":
    # quick CLI for debugging
    import json
    out = analyze_usb_file_access()
    print(json.dumps(out, indent=2))
