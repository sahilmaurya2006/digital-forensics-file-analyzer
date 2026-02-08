# Digital Forensics File Analyzer

Small CLI utility to extract basic file metadata, calculate hashes (MD5/SHA256), extract EXIF from images, and generate reports (CSV / JSON / PDF).

Features
- Recursively scan a folder and collect filename, path, timestamps, size, MD5 and SHA256.
- EXIF extraction for common image formats (JPEG, TIFF, PNG where available).
- Export reports as CSV, JSON (wrapped with metadata), and a simple PDF summary.
- CLI options for output directory, verbose logging, and duplicate detection.

Quickstart

1. Install dependencies (recommended inside a virtualenv):

```powershell
python -m pip install -r requirements.txt
```

2. Run the analyzer on a folder and generate JSON/CSV/PDF reports:

```powershell
python -m src.analyzer -f "sample_files" --json --csv --pdf -o "reports"
```

3. Common options:
- `-f/--folder` (required): folder to scan
- `--json`, `--csv`, `--pdf`: export formats
- `-o/--output-dir`: directory where reports will be written (defaults to `reports`)
- `--duplicates`: print duplicate files (by SHA256)
- `--verbose`: enable verbose logging

Notes
- The JSON output is wrapped with a small metadata object containing `generated_at` and `count`.
- The PDF is a simple readable summary intended for quick review; feel free to customize layout in `src/report_generator.py`.

Next steps / suggestions
- Add unit tests for `src/metadata_utils.py` and `src/analyzer.py`.
- Add a CI workflow (GitHub Actions) to run linting and tests on push.
- Improve PDF layout and add thumbnails for images (requires additional packages).

License

See `LICENSE` in the repository root.
