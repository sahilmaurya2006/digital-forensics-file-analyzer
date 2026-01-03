import json
import csv
import os
import sys

P = os.path.join('reports', 'usb_activity_annotated.json')
OUT = os.path.join('reports', 'usb_activity_annotated.csv')

if not os.path.exists(P):
    print('ERROR: annotated JSON not found:', P)
    sys.exit(2)

with open(P, 'r', encoding='utf-8') as fh:
    data = json.load(fh)

print('Loaded', len(data), 'records from', P)

preferred = ['drive', 'event_id', 'time_generated', 'message', 'log_name', 'before_hash', 'after_hash', 'status']
all_keys = set()
for d in data:
    all_keys.update(d.keys())
rest = sorted(k for k in all_keys if k not in preferred)
fields = [k for k in preferred if k in all_keys] + rest

with open(OUT, 'w', encoding='utf-8', newline='') as fh:
    writer = csv.DictWriter(fh, fieldnames=fields)
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, '') for k in fields})

print('WROTE', OUT)
