import sys
import logging
import shutil
from datetime import datetime

# Configure logging to both stdout and a log file in reports/
log_dir = 'reports'
shutil.os.makedirs(log_dir, exist_ok=True)
logfile = shutil.os.path.join(log_dir, 'analyzer_run_capture.log')

root = logging.getLogger()
root.setLevel(logging.DEBUG)
# remove existing handlers
for h in list(root.handlers):
    root.removeHandler(h)

fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(fmt)
root.addHandler(ch)
fh = logging.FileHandler(logfile, encoding='utf-8')
fh.setLevel(logging.DEBUG)
fh.setFormatter(fmt)
root.addHandler(fh)

# Build argv for analyzer - mirror what we used before
args = [
    'analyzer',
    '-f', 'sample_files',
    '--usb-scan', '--usb-evtx', 'tools\\usb_sample.txt',
    '--win-artifacts', '--json', '--csv', '--pdf',
    '-o', 'reports',
    '--suspicious-threshold', '30',
    '--verbose'
]

# Inject into sys.argv and call main
sys.argv = [sys.argv[0]] + args
try:
    from src import analyzer
    analyzer.main()
    print('ANALYZER_EXITED_OK')
except SystemExit as e:
    print('ANALYZER_SYSTEM_EXIT', e)
except Exception:
    logging.exception('Analyzer crashed')
    raise
