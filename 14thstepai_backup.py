import importlib.util
import json
import os
import re
import time
from typing import Dict, List

import requests


STEP11_PATH = r"C:\sri\trisulauto\11thsteptest.py"
TCP_REPORT_HTML = r"C:\sri\trisulauto\tcp-report.html"
GROUP_ID = "e59ba4ef-8c9c-485a-9c4f-7b7c8de0dd45"
VM_BASE_URL = "https://dev-admin-console.zybisys.com/api/admin-api/vm-performance"
HEADERS = {"X-SECRET-KEY": "A0tziuB02IrdIS"}


def get_time_range() -> tuple[int, int]:
	"""Return last one-hour window in epoch milliseconds."""
	to_ts = int(time.time() * 1000)
	from_ts = to_ts - (60 * 60 * 1000)
	return from_ts, to_ts


def _to_float(value, default: float = 0.0) -> float:
	try:
		return float(value)
	except (TypeError, ValueError):
		return default


def _load_step11_module():
	spec = importlib.util.spec_from_file_location("step11_module", STEP11_PATH)
	if spec is None or spec.loader is None:
		raise RuntimeError(f"Unable to load module from {STEP11_PATH}")
	step11 = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(step11)
	return step11


def get_ips_from_step11() -> List[str]:
	"""Rebuild 11thsteptest.py IP array logic and return unique IPs in order."""
	step11 = _load_step11_module()

	to_sec = int(time.time())
	from_sec = to_sec - 3600

	meter_labels, _, _ = step11.fetch_counter_group_info(GROUP_ID)
	meter_results = {}
	for meter in sorted(meter_labels.keys()):
		meter_results[meter] = step11.fetch_topper_keys(GROUP_ID, meter, from_sec, to_sec, maxitems=5)

	ranked_ips = []
	for meter, entries in meter_results.items():
		for rank, entry in enumerate(entries, start=1):
			ranked_ips.append({"meter": meter, "rank": rank, "ip": entry["ip"]})

	ip_list = [item["ip"] for item in ranked_ips]

	unique_ips = []
	seen = set()
	for ip in ip_list:
		if ip not in seen:
			seen.add(ip)
			unique_ips.append(ip)
	if unique_ips:
		return unique_ips

	return get_ips_from_report_html(TCP_REPORT_HTML)


def get_ips_from_report_html(report_path: str) -> List[str]:
	"""Fallback: extract IP keys from PREFETCH_IP_TOP_VALUES in tcp-report.html."""
	if not os.path.exists(report_path):
		return []

	try:
		with open(report_path, "r", encoding="utf-8") as f:
			html = f.read()
	except OSError:
		return []

	match = re.search(r"\bPREFETCH_IP_TOP_VALUES\s*=\s*(\{.*?\});", html, flags=re.DOTALL)
	if not match:
		return []

	try:
		parsed = json.loads(match.group(1))
	except json.JSONDecodeError:
		return []

	if not isinstance(parsed, dict):
		return []

	return [str(ip).strip() for ip in parsed.keys() if str(ip).strip()]


def get_internal_ips_from_report_html(report_path: str) -> List[str]:
	"""Extract only INTERNAL ISSUE IPs from tcp-report.html, excluding EXTERNAL and BOTH."""
	if not os.path.exists(report_path):
		return []

	try:
		with open(report_path, "r", encoding="utf-8") as f:
			html = f.read()
	except OSError:
		return []

	# Pattern: data-ip="X.X.X.X" ... <div class="classification internal">🎯 INTERNAL ISSUE</div>
	pattern = r'data-ip="([^"]+)".*?<div class="classification internal">🎯 INTERNAL ISSUE</div>'
	matches = re.findall(pattern, html, flags=re.DOTALL)
	
	# Deduplicate while preserving order
	unique_ips = []
	seen = set()
	for ip in matches:
		if ip not in seen:
			seen.add(ip)
			unique_ips.append(ip)
	
	return unique_ips


def fetch_vm_metrics(ip: str) -> Dict[str, float]:
	from_ts, to_ts = get_time_range()
	url = f"{VM_BASE_URL}/{ip}?from={from_ts}&to={to_ts}"

	try:
		response = requests.get(url, headers=HEADERS, timeout=10)
		response.raise_for_status()
		data = response.json()
	except Exception:
		return {"cpu": 0.0, "ram": 0.0, "tcp": 0.0}

	cpu_vals = []
	ram_vals = []
	tcp_vals = []

	for entry in data.get("message", []):
		cpu_vals.append(_to_float(entry.get("cpu", {}).get("percent_used", 0)))
		ram_vals.append(_to_float(entry.get("ram", {}).get("percent_used", 0)))
		tcp_vals.append(_to_float(entry.get("tcp_connection", {}).get("established", 0)))

	if not cpu_vals:
		return {"cpu": 0.0, "ram": 0.0, "tcp": 0.0}

	return {
		"cpu": round(sum(cpu_vals) / len(cpu_vals), 2),
		"ram": round(sum(ram_vals) / len(ram_vals), 2),
		"tcp": round(sum(tcp_vals) / len(tcp_vals), 2),
	}


def main():
	# Extract only INTERNAL ISSUE IPs from the HTML report
	ips = get_internal_ips_from_report_html(TCP_REPORT_HTML)
	
	if not ips:
		print("No INTERNAL ISSUE IPs found in the report")
		return
	
	print(f"Found {len(ips)} INTERNAL ISSUE IPs from tcp-report.html")

	for ip in ips:
		metrics = fetch_vm_metrics(ip)
		print(f"\nIP: {ip}")
		print("Averaged Metrics:\n")
		print(f"CPU Average: {metrics['cpu']:.2f}%")
		print(f"RAM Average: {metrics['ram']:.2f}%")
		print(f"TCP Established Average: {metrics['tcp']:.2f}")


if __name__ == "__main__":
	main()
