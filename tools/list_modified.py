import os
import datetime
import argparse
from typing import List


def parse_date(s: str) -> datetime.datetime:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
    raise ValueError(f"Invalid date format: {s}. Use YYYY-MM-DD")


def load_excludes(raw: str) -> List[str]:
    if not raw:
        return [".venv"]
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    # always ensure .venv is excluded by default
    if '.venv' not in parts:
        parts.append('.venv')
    return parts


def main() -> None:
    parser = argparse.ArgumentParser(description="List files modified in a date range")
    parser.add_argument("--root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')),
                        help="Project root to scan (default: repository root)")
    parser.add_argument("--start", default="2025-10-01", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", default="2025-11-10", help="End date (YYYY-MM-DD)")
    parser.add_argument("--exclude", help="Comma-separated list of folders to exclude (e.g. .venv,node_modules)")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    start = parse_date(args.start)
    # make end inclusive by setting to end of day
    end_date = parse_date(args.end)
    end = datetime.datetime(end_date.year, end_date.month, end_date.day, 23, 59, 59)

    excludes = load_excludes(args.exclude)
    norm_excludes = [os.path.normcase(os.path.abspath(os.path.join(root, p))) if not os.path.isabs(p) else os.path.normcase(os.path.abspath(p)) for p in excludes]

    matches = []
    for dirpath, dirs, files in os.walk(root):
        # skip excluded directories
        norm_dir = os.path.normcase(os.path.abspath(dirpath))
        if any(norm_dir == ex or norm_dir.startswith(ex + os.sep) for ex in norm_excludes):
            continue
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                m = datetime.datetime.fromtimestamp(os.path.getmtime(p))
            except Exception:
                continue
            if start <= m <= end:
                matches.append((p, m))

    matches.sort(key=lambda x: x[1])
    print(f"Found {len(matches)} files modified between {start.date()} and {end.date()}:")
    for p, m in matches:
        rel = os.path.relpath(p, root)
        print(f"- {rel} (Modified: {m.strftime('%Y-%m-%d')})")


if __name__ == '__main__':
    main()

