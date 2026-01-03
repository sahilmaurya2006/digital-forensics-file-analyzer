from src.usb_devices import find_usb_device_events, save_results

if __name__ == '__main__':
    # Try to parse sample file fallback by default so it works in this environment
    evtx = 'tools/usb_sample.txt'
    results = find_usb_device_events(evtx_path=evtx)
    out = save_results(results, output_dir='reports', base_name='usb_devices')
    print(f'Found {len(results)} USB device-related events. Saved: {out}')
