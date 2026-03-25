import argparse
import json
import re
from datetime import datetime, timezone
from html import unescape
from pathlib import Path


# ---------------------------------------------------------------------------
# Infra helpers (replicated from 11thstep.py — no ZMQ/protobuf dependencies)
# ---------------------------------------------------------------------------

def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _series_stats(series):
    numbers = [_to_float(v) for v in (series or [])]
    if not numbers:
        return {"latest": 0.0, "avg": 0.0, "peak": 0.0}
    return {
        "latest": numbers[-1],
        "avg": round(sum(numbers) / len(numbers), 4),
        "peak": max(numbers),
    }


def _load_json_file(path, label):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        print(f"Warning: {label} file is not a JSON object: {path}")
        return {}
    except FileNotFoundError:
        print(f"Warning: {label} file not found: {path}")
    except json.JSONDecodeError as exc:
        print(f"Warning: invalid JSON in {label} file {path}: {exc}")
    except OSError as exc:
        print(f"Warning: unable to read {label} file {path}: {exc}")
    return {}


def build_infra_snapshot(vm_data, ram_data, cpu_data):
    vm = vm_data if isinstance(vm_data, dict) else {}
    ram_msg = ram_data.get("message", {}) if isinstance(ram_data, dict) else {}
    cpu_msg = cpu_data.get("message", {}) if isinstance(cpu_data, dict) else {}

    cpu_stats = _series_stats(cpu_msg.get("used", []))
    ram_stats = _series_stats(ram_msg.get("percent_used", []))

    ram_used_series = ram_msg.get("used", [])
    ram_total_series = ram_msg.get("total", [])
    ram_used_latest = _to_float(ram_used_series[-1], 0.0) if ram_used_series else 0.0
    ram_total_latest = _to_float(ram_total_series[-1], 0.0) if ram_total_series else 0.0

    if ram_stats["latest"] <= 0 and ram_used_latest > 0 and ram_total_latest > 0:
        ram_stats["latest"] = (ram_used_latest / ram_total_latest) * 100

    warn_cpu = _to_float((cpu_msg.get("warn", [0]) or [0])[-1], 0.0)
    crit_cpu = _to_float((cpu_msg.get("crit", [0]) or [0])[-1], 0.0)
    warn_ram = _to_float((ram_msg.get("warn", [0]) or [0])[-1], 0.0)
    crit_ram = _to_float((ram_msg.get("crit", [0]) or [0])[-1], 0.0)

    timestamp_epoch = int(_to_float((ram_msg.get("time_str", [0]) or [0])[-1], 0.0))
    if timestamp_epoch <= 0:
        timestamp_epoch = int(_to_float((cpu_msg.get("time_str", [0]) or [0])[-1], 0.0))

    return {
        "vm": {
            "hostname": str(vm.get("vm_hostname") or vm.get("vm_server_hostname") or "-"),
            "lan_ip": str(vm.get("lan_ip") or "-"),
            "wan_ip": str(vm.get("wan_ip") or "-"),
            "cpu_cores": vm.get("cpu", "-"),
            "ram": str(vm.get("ram") or "-"),
            "disk": str(vm.get("disk") or "-"),
            "power_status": str(vm.get("power_status") or "-"),
            "os": str(vm.get("vm_os") or "-"),
        },
        "cpu_stats": {
            "latest_pct": round(cpu_stats["latest"], 2),
            "avg_pct": round(cpu_stats["avg"], 2),
            "peak_pct": round(cpu_stats["peak"], 2),
            "warn_pct": round(warn_cpu, 2),
            "crit_pct": round(crit_cpu, 2),
        },
        "ram_stats": {
            "latest_pct": round(ram_stats["latest"], 2),
            "avg_pct": round(ram_stats["avg"], 2),
            "peak_pct": round(ram_stats["peak"], 2),
            "used_gb_latest": round(ram_used_latest, 2),
            "total_gb": round(ram_total_latest, 2),
            "warn_pct": round(warn_ram, 2),
            "crit_pct": round(crit_ram, 2),
        },
        "timestamp_epoch": timestamp_epoch,
    }


def load_infra_snapshot(vm_path, ram_path, cpu_path):
    vm_data = _load_json_file(vm_path, "VM metadata")
    ram_data = _load_json_file(ram_path, "RAM resources")
    cpu_data = _load_json_file(cpu_path, "CPU resources")
    return build_infra_snapshot(vm_data, ram_data, cpu_data)


def is_same_network(ip1, ip2, subnet_mask="255.255.255.0"):
    try:
        p1 = [int(x) for x in str(ip1).split(".")]
        p2 = [int(x) for x in str(ip2).split(".")]
        pm = [int(x) for x in str(subnet_mask).split(".")]
        if len(p1) != 4 or len(p2) != 4 or len(pm) != 4:
            return False
        return all((p1[i] & pm[i]) == (p2[i] & pm[i]) for i in range(4))
    except Exception:
        return False


def get_infra_for_ip(ip, infra_snapshot):
    if not isinstance(infra_snapshot, dict):
        return None
    vm = infra_snapshot.get("vm", {})
    lan_ip = str(vm.get("lan_ip", "") or "").strip()
    wan_ip = str(vm.get("wan_ip", "") or "").strip()
    if lan_ip and is_same_network(ip, lan_ip):
        return {**infra_snapshot, "route": "LAN"}
    if wan_ip and is_same_network(ip, wan_ip):
        return {**infra_snapshot, "route": "WAN"}
    return None


def clean_text(value):
    text = re.sub(r"<[^>]+>", "", value or "")
    text = unescape(text)
    text = text.replace("\xa0", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text.lstrip("• ").strip()


def extract_js_json(html_text, variable_name):
    pattern = rf"var\s+{re.escape(variable_name)}\s*=\s*(.*?);"
    match = re.search(pattern, html_text, re.S)
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def parse_report_header(html_text):
    header_match = re.search(
        r'<div class="timestamp">Generated:\s*(.*?)\s*\|\s*Time Range:.*?\(from\s*(.*?)\s*to\s*(.*?)\)</div>',
        html_text,
        re.S,
    )
    report = {
        "generated_at": None,
        "window_start": None,
        "window_end": None,
    }
    if header_match:
        report["generated_at"] = clean_text(header_match.group(1))
        report["window_start"] = clean_text(header_match.group(2))
        report["window_end"] = clean_text(header_match.group(3))
    return report


def parse_system_resources(html_text):
    items = re.findall(
        r'<div class="infra-item"><span class="infra-label">(.*?):</span>(.*?)</div>',
        html_text,
        re.S,
    )

    mapping = {
        "CPU Usage": "cpu_usage",
        "RAM Usage": "ram_usage",
        "RAM": "ram_size",
        "Disk": "disk_size",
    }

    result = {}
    for label, value in items:
        key = mapping.get(clean_text(label), clean_text(label).lower().replace(" ", "_"))
        result[key] = clean_text(value)
    return result


def parse_meter_summary(section_html):
    match = re.search(
        r'Min:\s*(.*?)\s*\|\s*Max:\s*(.*?)\s*\|\s*Avg:\s*(.*?)\s*\|\s*Latest:\s*(.*?)\s*</div>',
        section_html,
        re.S,
    )
    if not match:
        return {}
    return {
        "min": clean_text(match.group(1)),
        "max": clean_text(match.group(2)),
        "avg": clean_text(match.group(3)),
        "latest": clean_text(match.group(4)),
    }


def parse_rule_section(analysis_html, section_name):
    if section_name == "problem":
        match = re.search(r'<h4>.*?Problem:.*?</h4>\s*<p>(.*?)</p>', analysis_html, re.S)
        return clean_text(match.group(1)) if match else None

    match = re.search(rf'<h4>.*?{section_name}:.*?</h4>\s*<ul>(.*?)</ul>', analysis_html, re.S | re.I)
    if not match:
        return []
    return [clean_text(item) for item in re.findall(r'<li>(.*?)</li>', match.group(1), re.S) if clean_text(item)]


def parse_analysis_block(analysis_html):
    issue_metrics = []
    for metric_name, metric_value in re.findall(
        r'<div class="issue-metric">.*?([^:<]+):\s*<strong>(.*?)</strong></div>',
        analysis_html,
        re.S,
    ):
        issue_metrics.append(
            {
                "name": clean_text(metric_name),
                "value": clean_text(metric_value),
            }
        )

    class_match = re.search(r'<div class="classification[^"]*">(.*?)</div>', analysis_html, re.S)
    classification = clean_text(class_match.group(1)).replace("🎯", "").strip() if class_match else None

    infra_match = re.search(
        r'<div class="issue-infra"><strong>Infra Route:</strong>\s*(.*?)\s*\|\s*<strong>Hostname:</strong>\s*(.*?)</div>',
        analysis_html,
        re.S,
    )
    infra = None
    if infra_match:
        infra = {
            "route": clean_text(infra_match.group(1)),
            "hostname": clean_text(infra_match.group(2)),
        }

    return {
        "issue_metrics": issue_metrics,
        "classification": classification,
        "infra": infra,
        "problem": parse_rule_section(analysis_html, "problem"),
        "diagnostics": parse_rule_section(analysis_html, "diagnostics"),
        "fix": parse_rule_section(analysis_html, "fix"),
    }


def parse_meter_sections(html_text, prefetch_top_values, prefetch_geo, prefetch_flow_issues):
    sections = re.findall(
        r'<div class="meter-section">(.*?)</div>\s*(?=<div class="meter-section">|<script>)',
        html_text,
        re.S,
    )

    issues = []
    for section_html in sections:
        meter_header_match = re.search(
            r'<span class="meter-id">(\d+)</span>(.*?)(?:<div class="meter-stats">|</div>)',
            section_html,
            re.S,
        )
        if not meter_header_match:
            continue

        meter_id = int(meter_header_match.group(1))
        meter_name = clean_text(meter_header_match.group(2))
        meter_summary = parse_meter_summary(section_html)

        entry_pattern = re.compile(
            r'<tr>\s*<td>(?P<rank>\d+)</td>\s*<td><button class="ip-link" data-ip="(?P<ip>[^"]+)"[^>]*>.*?</button></td>\s*</tr>'
            r'.*?'
            r'<tr>\s*<td colspan="3">\s*<div class="ip-analysis">(?P<analysis>.*?)</div>\s*</td>\s*</tr>',
            re.S,
        )

        for match in entry_pattern.finditer(section_html):
            ip = clean_text(match.group("ip"))
            analysis = parse_analysis_block(match.group("analysis"))
            top_value_payload = prefetch_top_values.get(ip, {}) if isinstance(prefetch_top_values, dict) else {}

            issues.append(
                {
                    "meter_id": meter_id,
                    "meter_name": meter_name,
                    "meter_summary": meter_summary,
                    "rank": int(match.group("rank")),
                    "ip": ip,
                    "classification": analysis["classification"],
                    "issue_metrics": analysis["issue_metrics"],
                    "rule": {
                        "problem": analysis["problem"],
                        "diagnostics": analysis["diagnostics"],
                        "fix": analysis["fix"],
                    },
                    "geo": prefetch_geo.get(ip, {}) if isinstance(prefetch_geo, dict) else {},
                    "top_values": top_value_payload.get("metrics", []),
                    "infra": analysis["infra"] or top_value_payload.get("infra"),
                    "flow_issues": prefetch_flow_issues.get(ip, []) if isinstance(prefetch_flow_issues, dict) else [],
                }
            )

    return issues


def extract_report(html_path, vm_path=None, ram_path=None, cpu_path=None):
    html_text = Path(html_path).read_text(encoding="utf-8")

    prefetch_flow_issues = extract_js_json(html_text, "PREFETCH_FLOW_ISSUES")
    prefetch_top_values = extract_js_json(html_text, "PREFETCH_IP_TOP_VALUES")
    prefetch_geo = extract_js_json(html_text, "PREFETCH_IP_GEO")

    # Load and build rich infra snapshot from Python JSON source files.
    infra_snapshot = None
    if vm_path and ram_path and cpu_path:
        infra_snapshot = load_infra_snapshot(vm_path, ram_path, cpu_path)

    # Merge system data: HTML-side display strings + Python-side numeric detail.
    html_system = parse_system_resources(html_text)
    merged_system = dict(html_system)
    if infra_snapshot:
        merged_system["vm"] = infra_snapshot["vm"]
        merged_system["cpu_stats"] = infra_snapshot["cpu_stats"]
        merged_system["ram_stats"] = infra_snapshot["ram_stats"]
        merged_system["timestamp_epoch"] = infra_snapshot["timestamp_epoch"]

    issues = parse_meter_sections(
        html_text,
        prefetch_top_values=prefetch_top_values,
        prefetch_geo=prefetch_geo,
        prefetch_flow_issues=prefetch_flow_issues,
    )

    # Enrich each issue's infra field using Python IP-to-subnet matching.
    if infra_snapshot:
        for issue in issues:
            if issue.get("infra") is None:
                matched = get_infra_for_ip(issue["ip"], infra_snapshot)
                if matched:
                    issue["infra"] = matched

    sources = {"html": str(Path(html_path).resolve())}
    if vm_path:
        sources["vm_json"] = str(Path(vm_path).resolve())
    if ram_path:
        sources["ram_json"] = str(Path(ram_path).resolve())
    if cpu_path:
        sources["cpu_json"] = str(Path(cpu_path).resolve())

    payload = {
        "sources": sources,
        "extracted_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report": parse_report_header(html_text),
        "system": merged_system,
        "issues": issues,
    }
    payload["issue_count"] = len(payload["issues"])
    return payload


def main():
    parser = argparse.ArgumentParser(description="Extract structured JSON from tcp-report.html + 11thstep.py JSON sources")
    parser.add_argument(
        "--input",
        default=r"C:\sri\trisulauto\tcp-report.html",
        help="Path to the generated HTML report",
    )
    parser.add_argument(
        "--output",
        default=r"C:\sri\trisulauto\html_extractor_output.json",
        help="Path to write the extracted JSON payload",
    )
    parser.add_argument(
        "--vm-json",
        default=r"C:\sri\trisulauto\vm_data.json",
        help="Path to vm_data.json (from 11thstep.py)",
    )
    parser.add_argument(
        "--ram-json",
        default=r"C:\sri\trisulauto\ram_resources.json",
        help="Path to ram_resources.json (from 11thstep.py)",
    )
    parser.add_argument(
        "--cpu-json",
        default=r"C:\sri\trisulauto\CPU_resources.json",
        help="Path to CPU_resources.json (from 11thstep.py)",
    )
    args = parser.parse_args()

    payload = extract_report(
        args.input,
        vm_path=args.vm_json,
        ram_path=args.ram_json,
        cpu_path=args.cpu_json,
    )
    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Extracted {payload['issue_count']} issue records")
    print(f"Sources merged: HTML + vm_data.json + ram_resources.json + CPU_resources.json")
    print(f"JSON written to: {output_path}")


if __name__ == "__main__":
    main()