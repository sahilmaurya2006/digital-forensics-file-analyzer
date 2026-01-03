import os
import argparse
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from tqdm import tqdm
from colorama import Fore, Style, init

from src.metadata_utils import calculate_hashes, get_file_basic_metadata, extract_exif
from src.report_generator import save_to_csv, save_to_json, save_to_pdf
from src.suspicious_detector import get_suspicion_score

init(autoreset=True)

# ------------------- Logging Setup -------------------
logger = logging.getLogger("dffa")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# Also add a file handler in the reports directory so runs always produce a log file.
try:
    os.makedirs("reports", exist_ok=True)
    fh = logging.FileHandler(os.path.join("reports", "analyzer.log"), encoding='utf-8')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
except Exception:
    # if we cannot create a file handler, continue without failing
    pass


# ------------------- File Analysis -------------------
def analyze_file(file_path: str, dry_run: bool = False) -> Dict[str, Any]:
    """Return metadata for a single file.

    If dry_run is True, only collect basic metadata and skip expensive operations
    like hashing, EXIF extraction and suspicion scoring.
    """
    base = get_file_basic_metadata(file_path)
    if not base:
        logger.debug("Skipping unreadable file: %s", file_path)
        return None

    if dry_run:
        # In dry-run we only return lightweight metadata
        base.update({"md5": None, "sha256": None, "suspicion_score": 0, "reasons": []})
        return base

    # Full analysis
    md5, sha256 = calculate_hashes(file_path)
    base.update({"md5": md5, "sha256": sha256})

    # Suspicion scoring expects metadata dict and returns (score, reasons)
    try:
        score, reasons = get_suspicion_score(base)
        base.update({"suspicion_score": score, "reasons": reasons})
    except Exception:
        # If detector fails, provide safe defaults
        base.update({"suspicion_score": 0, "reasons": []})

    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".jpg", ".jpeg", ".tiff", ".png"]:
        try:
            base["exif"] = extract_exif(file_path)
        except Exception:
            base["exif"] = {}

    return base


def analyze_folder(folder_path: str, include_exts: List[str] = None, exclude_list: List[str] = None, dry_run: bool = False) -> List[Dict[str, Any]]:
    """Recursively analyze files in folder_path.

    include_exts: optional list of lowercase extensions (e.g. ['.jpg', '.pdf']) to limit files.
    exclude_list: optional list of absolute normalized paths to skip (files or directories).
    dry_run: if True, do lightweight metadata collection only.
    """
    results = []
    logger.info("Scanning folder: %s", folder_path)
    norm_excludes = [os.path.normcase(os.path.abspath(p)) for p in (exclude_list or [])]

    for root, _, files in os.walk(folder_path):
        for file in tqdm(files, desc="Files", ncols=80):
            path = os.path.join(root, file)
            abs_path = os.path.normcase(os.path.abspath(path))

            # Check excludes: exact file match or parent directory match
            skip = False
            for ex in norm_excludes:
                if abs_path == ex or abs_path.startswith(ex + os.sep):
                    skip = True
                    logger.debug("Excluded path: %s", path)
                    break
            if skip:
                continue

            # Extension filter
            if include_exts:
                ext = os.path.splitext(file)[1].lower()
                if ext not in include_exts:
                    logger.debug("Skipping %s due to extension filter", path)
                    continue

            metadata = analyze_file(path, dry_run=dry_run)
            if metadata:
                results.append(metadata)
    return results


# ------------------- Utility Functions -------------------
def find_duplicates(results: List[Dict[str, Any]]) -> List[tuple]:
    seen = {}
    duplicates = []
    for r in results:
        h = r.get("sha256")
        if not h:
            continue
        if h in seen:
            duplicates.append((r["path"], seen[h]))
        else:
            seen[h] = r["path"]
    return duplicates


def find_recently_modified(results: List[Dict[str, Any]], from_date=None, to_date=None) -> List[Dict[str, Any]]:
    """Return files modified between given date range."""
    if not from_date and not to_date:
        cutoff = datetime.now() - timedelta(days=10)
        return [r for r in results if datetime.fromisoformat(r["modified"]) >= cutoff]

    try:
        if from_date:
            from_date = datetime.strptime(from_date, "%Y-%m-%d")
        if to_date:
            to_date = datetime.strptime(to_date, "%Y-%m-%d")
    except ValueError:
        logger.error("Invalid date format! Use YYYY-MM-DD")
        return []

    filtered = []
    for r in results:
        try:
            modified_time = datetime.fromisoformat(r["modified"])
            if (not from_date or modified_time >= from_date) and (not to_date or modified_time <= to_date):
                filtered.append(r)
        except Exception:
            continue
    return filtered


# ------------------- Main -------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Digital Forensics File Analyzer")
    parser.add_argument("-f", "--folder", required=True, help="Folder to analyze")
    parser.add_argument("--csv", action="store_true", help="Export CSV")
    parser.add_argument("--json", action="store_true", help="Export JSON")
    parser.add_argument("--pdf", action="store_true", help="Export PDF")
    parser.add_argument("--duplicates", action="store_true", help="Find duplicate files")
    parser.add_argument("--recent", action="store_true", help="Files modified in the last 10 days")
    parser.add_argument("--from-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--to-date", help="End date (YYYY-MM-DD)")
    parser.add_argument("-o", "--output-dir", default="reports", help="Output directory for reports")
    parser.add_argument("--exclude", help="Comma-separated list of folders or files to exclude from scanning")
    parser.add_argument("--ext", help="Comma-separated list of extensions to include (e.g. .jpg,.pdf or jpg,pdf)")
    parser.add_argument("--dry-run", action="store_true", help="List files that would be scanned without hashing or extracting metadata")
    parser.add_argument("--suspicious-threshold", type=int, default=None, help="If set, also write a suspicious report for files with score >= threshold")
    parser.add_argument("--file", help="Analyze a single file and print metadata to stdout (JSON)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--usb-scan", action="store_true", help="Scan Windows Event Logs for USB file access")
    parser.add_argument("--usb-drives", help="Comma-separated list of drive letters to check (e.g. E:,F:)")
    parser.add_argument("--usb-logs", help="Comma-separated list of event log names to read (default: Security)")
    parser.add_argument("--usb-evtx", help="Path to exported event log or text file to parse as fallback when pywin32 is unavailable")
    parser.add_argument("--win-artifacts", action="store_true", help="Collect Windows artifacts: Prefetch, Recent files, drive info")
    parser.add_argument("--keylogger-scan", action="store_true", help="Run heuristic keylogger detection (processes, drivers, registry)")
    parser.add_argument("--prefetch-dir", help="Alternate Prefetch directory to scan")
    parser.add_argument("--recent-dir", help="Alternate Recent directory to scan")
    parser.add_argument("--artifact-drives", help="Comma-separated drive letters to check for volume info")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not os.path.exists(args.folder):
        logger.error("Folder not found: %s", args.folder)
        return

    # build exclude list
    exclude_list = []
    if args.exclude:
        for e in args.exclude.split(','):
            p = e.strip()
            if not p:
                continue
            # store absolute normalized path
            exclude_list.append(os.path.abspath(p))

    # extension filter
    include_exts = None
    if args.ext:
        include_exts = []
        for ex in args.ext.split(','):
            e = ex.strip().lower()
            if not e:
                continue
            if not e.startswith('.'):
                e = '.' + e
            include_exts.append(e)

    # single file mode
    if args.file:
        # analyze single file and print JSON
        single = analyze_file(args.file, dry_run=args.dry_run)
        import json
        print(json.dumps(single, indent=2, default=str))
        return

    results = analyze_folder(args.folder, include_exts=include_exts, exclude_list=exclude_list, dry_run=args.dry_run)
    if not results:
        logger.warning("No files found.")
        return

    os.makedirs(args.output_dir, exist_ok=True)

    # Duplicate detection
    if args.duplicates:
        dups = find_duplicates(results)
        if dups:
            logger.warning("Duplicates found:")
            for a, b in dups:
                logger.warning("  %s == %s", a, b)
        else:
            logger.info("No duplicates detected.")

    # Recent or date-range detection
    if args.recent or args.from_date or args.to_date:
        recent_files = find_recently_modified(results, args.from_date, args.to_date)
        if recent_files:
            logger.info(Fore.CYAN + f"\nFiles modified in specified range ({len(recent_files)} found):")
            for r in recent_files:
                print(Fore.YELLOW + f"{r['filename']}  |  Modified: {r['modified']}")
        else:
            logger.info(Fore.GREEN + "No files found in that date range.")

    # Exports
    if args.csv:
        path = save_to_csv(results, output_dir=args.output_dir)
        logger.info("CSV saved: %s", path)

    if args.json:
        path = save_to_json(results, output_dir=args.output_dir)
        logger.info("JSON saved: %s", path)

    if args.pdf:
        path = save_to_pdf(results, output_dir=args.output_dir)
        logger.info("PDF saved: %s", path)

    # Suspicious report
    if args.suspicious_threshold is not None:
        try:
            thr = int(args.suspicious_threshold)
            flagged = [r for r in results if r.get('suspicion_score', 0) >= thr]
            if flagged:
                sjson = save_to_json(flagged, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'suspicious.json'))
                scsv = save_to_csv(flagged, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'suspicious.csv'))
                logger.info("Suspicious report saved: %s, %s", sjson, scsv)
            else:
                logger.info("No files met the suspicious threshold of %d", thr)
        except Exception:
            logger.error("Failed to write suspicious report")

    logger.info("Analysis complete.")

    # Optional: USB event log scan
    if args.usb_scan:
        try:
            from src.usb_audit import analyze_usb_file_access
            drives = None
            if args.usb_drives:
                drives = [d.strip() for d in args.usb_drives.split(',') if d.strip()]
            logs = None
            if args.usb_logs:
                logs = [l.strip() for l in args.usb_logs.split(',') if l.strip()]
            logger.info("Running USB event-log scan (drives=%s logs=%s)", drives or "default", logs or "Security")
            # pass evtx path if provided
            if args.usb_evtx:
                usb_activity = analyze_usb_file_access(drive_letters=drives, log_names=logs, evtx_path=args.usb_evtx)
                # annotate usb activity with before/after hashes using last_scan.json
                try:
                    from src.usb_audit import annotate_usb_activity_with_hashes
                    history_file = os.path.join(args.output_dir, 'last_scan.json') if os.path.exists(os.path.join(args.output_dir, 'last_scan.json')) else os.path.join('reports', 'last_scan.json')
                    usb_activity = annotate_usb_activity_with_hashes(usb_activity, history_path=history_file)
                except Exception:
                    pass
            else:
                usb_activity = analyze_usb_file_access(drive_letters=drives, log_names=logs)
            if usb_activity:
                sjson = save_to_json(usb_activity, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'usb_activity.json'))
                scsv = save_to_csv(usb_activity, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'usb_activity.csv'))
                logger.info("USB activity saved: %s, %s", sjson, scsv)
            else:
                logger.info("No USB activity found or pywin32 unavailable.")
        except Exception as e:
            logger.error("USB scan failed: %s", e)

    # Windows artifacts
    if args.win_artifacts:
        try:
            from src.windows_artifacts import gather_all
            drives = None
            if args.artifact_drives:
                drives = [d.strip() for d in args.artifact_drives.split(',') if d.strip()]
            win_data = gather_all(prefetch_dir=args.prefetch_dir, recent_dir=args.recent_dir, drive_letters=drives)
            # save separately to avoid heterogeneous CSV field issues
            prefetch = win_data.get('prefetch', [])
            recent = win_data.get('recent', [])
            drives_info = win_data.get('drives', [])
            p_j = save_to_json(prefetch, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_prefetch.json'))
            p_c = save_to_csv(prefetch, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_prefetch.csv'))
            r_j = save_to_json(recent, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_recent.json'))
            r_c = save_to_csv(recent, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_recent.csv'))
            d_j = save_to_json(drives_info, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_drives.json'))
            d_c = save_to_csv(drives_info, output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'windows_drives.csv'))
            logger.info("Windows artifacts saved: %s, %s, %s", p_j, r_j, d_j)
        except Exception as e:
            logger.error("Failed to collect Windows artifacts: %s", e)

    # Keylogger detection (heuristic)
    if args.keylogger_scan:
        try:
            from src.keylogger_detector import detect_all
            kl = detect_all()
            kj = save_to_json(kl.get('process_findings', []) + kl.get('driver_findings', []) + kl.get('registry_findings', []), output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'keylogger_findings.json'))
            kc = save_to_csv(kl.get('process_findings', []) + kl.get('driver_findings', []) + kl.get('registry_findings', []), output_dir=args.output_dir, output_file=os.path.join(args.output_dir, 'keylogger_findings.csv'))
            logger.info("Keylogger detection saved: %s, %s", kj, kc)
        except Exception as e:
            logger.error("Keylogger detection failed: %s", e)


if __name__ == "__main__":
    main()
