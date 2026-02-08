import importlib, traceback
modules = ['src.suspicious_detector','src.keyword_scan','src.history_tracker','src.gps_mapper']
for m in modules:
    try:
        mod = importlib.import_module(m)
        print(m, 'OK', [n for n in dir(mod) if not n.startswith('_')])
    except Exception:
        traceback.print_exc()
