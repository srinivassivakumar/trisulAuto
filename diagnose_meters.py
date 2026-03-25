#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\sri\trisulauto')

from importlib.util import spec_from_file_location, module_from_spec
import time

# Import 11thsteptest dynamically
spec = spec_from_file_location("step11", r"C:\sri\trisulauto\11thsteptest.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

# Get configuration
group_id = 'SYS:CGI'
to_ts = int(time.time())
from_ts = to_ts - 3600

# Fetch meter results and IP data
meter_results = {}
meter_labels, _, _ = module.fetch_counter_group_info(group_id)

for meter in sorted(meter_labels.keys()):
    meter_results[meter] = module.fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems=5)

# Build IP to meters mapping
ip_to_meters = {}
suspect_ip_to_key = {}

for entries in meter_results.values():
    for item in entries:
        suspect_ip_to_key.setdefault(item["ip"], item["key"])

for ip, trisul_key in suspect_ip_to_key.items():
    all_meter_values = module.fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts)
    filtered_values = {m: v for m, v in all_meter_values.items() if m in meter_labels}
    ip_to_meters[ip] = {m for m, v in filtered_values.items() if v > 0}

# Check all IPs
print("IPs with their meters (including classification):")
print("-" * 80)

ips_with_0_2_4 = []
for ip, ip_meters in sorted(ip_to_meters.items()):
    meters_str = ', '.join(map(str, sorted(ip_meters))) if ip_meters else "NONE"
    classification = module.classify_issue(ip_meters)
    has_all_three = {0, 2, 4}.issubset(ip_meters)
    if has_all_three and classification == "INTERNAL ISSUE":
        ips_with_0_2_4.append(ip)
        marker = " *** MATCH ***"
    else:
        marker = ""
    print(f"{ip:18} | Meters: [{meters_str:30}] | {classification:30}{marker}")

print("-" * 80)
print(f"Total unique IPs: {len(ip_to_meters)}")
print(f"IPs with meters 0, 2, 4 AND INTERNAL classification: {len(ips_with_0_2_4)}")
