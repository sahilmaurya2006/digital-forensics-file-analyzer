import subprocess
import os
from datetime import datetime

log_dir = 'reports'
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, 'analyzer_debug.log')

cmd = [
    'python', '-u', '-m', 'src.analyzer',
    '-f', 'sample_files',
    '--usb-scan', '--usb-evtx', 'tools\\usb_sample.txt',
    '--win-artifacts', '--json', '--csv', '--pdf',
    '-o', 'reports',
    '--suspicious-threshold', '30',
    '--verbose'
]

with open(log_path, 'w', encoding='utf-8') as fh:
    fh.write(f'=== Analyzer run started at {datetime.utcnow().isoformat()}Z ===\n')
    fh.flush()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        fh.write(line)
        fh.flush()
    ret = proc.wait()
    fh.write(f'=== Analyzer exited with return code {ret} at {datetime.utcnow().isoformat()}Z ===\n')

print('WROTE', log_path, 'exit_code=', ret)
