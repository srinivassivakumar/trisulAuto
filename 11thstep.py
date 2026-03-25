import socket
import time
import json
import argparse
from threading import Thread
from datetime import datetime, timedelta, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import zmq
import trp_pb2
from location import get_ip_info

# Script purpose:
# - Query Trisul TCP analyzer counters
# - Build flow drill-down data
# - Generate interactive HTML report
# - Optionally serve HTTP API for IP flow details
# - Enrich output with VM/CPU/RAM snapshot data loaded from JSON files

TRISUL_HOST = "10.193.2.9"
TRISUL_PORT = 12001
RULE_FILE = r"C:\sri\trisulauto\network_issue_rules.json"
DEFAULT_VM_JSON = r"C:\sri\trisulauto\vm_data.json"
DEFAULT_RAM_JSON = r"C:\sri\trisulauto\ram_resources.json"
DEFAULT_CPU_JSON = r"C:\sri\trisulauto\CPU_resources.json"
IST_TZ = timezone(timedelta(hours=5, minutes=30))

GEO_CACHE = {}

METER_TO_METRIC = {
    0: "LAT",
    1: "LAT",
    2: "RPKT",
    3: "RPKT",
    4: "R%",
    5: "R%",
    6: "PQF",
    7: "TO",
    8: "UNI",
}

METER_FULL_NAMES = {
    0: "Latency Internal (µs)",
    1: "Latency External (µs)",
    2: "Retransmitted Packets Internal",
    3: "Retransmitted Packets External",
    4: "Retransmission Rate % Internal",
    5: "Retransmission Rate % External",
    6: "Poor Quality Flows",
    7: "Timeouts",
    8: "Unidirectional Flows",
}

INTERNAL_SET = {0, 2, 4, 6, 7, 8}
EXTERNAL_SET = {1, 3, 5, 6, 8}
SHARED_METERS = {6, 8}
INTERNAL_UNIQUE_METERS = INTERNAL_SET - SHARED_METERS
EXTERNAL_UNIQUE_METERS = EXTERNAL_SET - SHARED_METERS


def load_rules():
    """Load network issue classification rules from the configured JSON file."""
    with open(RULE_FILE, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    return data["rules"]


def _load_json_file(path, label):
    """Safely load a JSON object file and return {} on any read/parse error."""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        print(f"Warning: {label} file does not contain a JSON object: {path}")
        return {}
    except FileNotFoundError:
        print(f"Warning: {label} file not found: {path}")
    except json.JSONDecodeError as exc:
        print(f"Warning: invalid JSON in {label} file {path}: {exc}")
    except OSError as exc:
        print(f"Warning: unable to read {label} file {path}: {exc}")
    return {}


def load_vm_data(path):
    """Load VM metadata JSON."""
    return _load_json_file(path, "VM metadata")


def load_ram_resources(path):
    """Load RAM monitoring JSON."""
    return _load_json_file(path, "RAM resources")


def load_cpu_resources(path):
    """Load CPU monitoring JSON."""
    return _load_json_file(path, "CPU resources")


def _to_float(value, default=0.0):
    """Best-effort float conversion with fallback default."""
    try:
        return float(value)
    except Exception:
        return default


def _series_stats(series):
    """Return latest, average, and peak statistics for a numeric series."""
    numbers = [_to_float(v) for v in (series or [])]
    if not numbers:
        return {
            "latest": 0.0,
            "avg": 0.0,
            "peak": 0.0,
        }
    return {
        "latest": numbers[-1],
        "avg": sum(numbers) / len(numbers),
        "peak": max(numbers),
    }


def build_infra_snapshot(vm_data, ram_data, cpu_data):
    """Normalize VM, RAM, and CPU payloads into a single infra snapshot dict."""
    vm = vm_data if isinstance(vm_data, dict) else {}
    ram_msg = ram_data.get("message", {}) if isinstance(ram_data, dict) else {}
    cpu_msg = cpu_data.get("message", {}) if isinstance(cpu_data, dict) else {}

    cpu_used = cpu_msg.get("used", [])
    cpu_stats = _series_stats(cpu_used)

    ram_percent = ram_msg.get("percent_used", [])
    ram_stats = _series_stats(ram_percent)

    ram_used_series = ram_msg.get("used", [])
    ram_total_series = ram_msg.get("total", [])
    ram_used_latest = _to_float(ram_used_series[-1], 0.0) if ram_used_series else 0.0
    ram_total_latest = _to_float(ram_total_series[-1], 0.0) if ram_total_series else 0.0

    # Fallback RAM % calculation if percent series is missing/invalid.
    if ram_stats["latest"] <= 0 and ram_used_latest > 0 and ram_total_latest > 0:
        ram_stats["latest"] = (ram_used_latest / ram_total_latest) * 100

    warn_cpu = _to_float((cpu_msg.get("warn", [0]) or [0])[-1], 0.0)
    crit_cpu = _to_float((cpu_msg.get("crit", [0]) or [0])[-1], 0.0)
    warn_ram = _to_float((ram_msg.get("warn", [0]) or [0])[-1], 0.0)
    crit_ram = _to_float((ram_msg.get("crit", [0]) or [0])[-1], 0.0)

    timestamp_epoch = int(_to_float((ram_msg.get("time_str", [0]) or [0])[-1], 0.0))
    if timestamp_epoch <= 0:
        timestamp_epoch = int(_to_float((cpu_msg.get("time_str", [0]) or [0])[-1], 0.0))

    snapshot = {
        "vm": {
            "hostname": str(vm.get("vm_hostname") or vm.get("vm_server_hostname") or "-"),
            "lan_ip": str(vm.get("lan_ip") or "-"),
            "wan_ip": str(vm.get("wan_ip") or "-"),
            "cpu": vm.get("cpu", "-"),
            "ram": str(vm.get("ram") or "-"),
            "disk": str(vm.get("disk") or "-"),
            "power_status": str(vm.get("power_status") or "-"),
        },
        "cpu": {
            "latest_pct": round(cpu_stats["latest"], 2),
            "avg_pct": round(cpu_stats["avg"], 2),
            "peak_pct": round(cpu_stats["peak"], 2),
            "warn": round(warn_cpu, 2),
            "crit": round(crit_cpu, 2),
        },
        "ram": {
            "latest_pct": round(ram_stats["latest"], 2),
            "avg_pct": round(ram_stats["avg"], 2),
            "peak_pct": round(ram_stats["peak"], 2),
            "used_gb_latest": round(ram_used_latest, 2),
            "total_gb": round(ram_total_latest, 2),
            "warn": round(warn_ram, 2),
            "crit": round(crit_ram, 2),
        },
        "timestamp_epoch": timestamp_epoch,
    }

    return snapshot


def load_infra_snapshot(vm_path, ram_path, cpu_path):
    """Load and combine VM/RAM/CPU JSON files into one normalized snapshot."""
    vm_data = load_vm_data(vm_path)
    ram_data = load_ram_resources(ram_path)
    cpu_data = load_cpu_resources(cpu_path)
    return build_infra_snapshot(vm_data, ram_data, cpu_data)


def find_matching_rule(metrics, rules):
    """Find the best-matching diagnostic rule for detected metric abbreviations."""
    known_metrics = {"LAT", "RPKT", "R%", "PQF", "TO", "UNI"}
    metric_set = {m for m in metrics if m in known_metrics}

    single_metric_fallback = {
        "TO": {
            "issue_name": "Timeouts (TO)",
            "problem": "Frequent TCP timeouts indicate severe delay or packet delivery failures. Sessions may stall and applications can become intermittently unreachable.",
            "diagnostics": [
                "Check end-to-end RTT spikes and packet loss during incident windows",
                "Inspect firewall/NAT state tables for expiration or saturation",
                "Verify routing stability and return-path reachability",
            ],
            "fix": [
                "Stabilize congested or failing links and reduce non-critical traffic bursts",
                "Tune firewall/NAT session handling and capacity where needed",
                "Fix asymmetric routing or return-path filtering issues",
            ],
        }
    }

    def normalize_rule_metrics(rule):
        """Normalize rule metric list; infer from issue_name when needed."""
        explicit = [m for m in rule.get("metrics", []) if m in known_metrics]
        issue_name = rule.get("issue_name", "")
        inferred = []

        if isinstance(issue_name, str) and "+" in issue_name:
            for token in issue_name.split("+"):
                t = token.strip()
                if t in known_metrics and t not in inferred:
                    inferred.append(t)

        if inferred and (not explicit or set(explicit) != set(inferred) or len(explicit) != len(inferred)):
            return inferred
        return explicit

    def section_score(rule):
        """Score rule content quality based on problem/diagnostics/fix presence."""
        has_problem = bool(str(rule.get("problem", "")).strip())
        has_diagnostics = any(str(d).strip() for d in rule.get("diagnostics", []))
        has_fix = any(str(f).strip() for f in rule.get("fix", []))
        return (1 if has_problem else 0) + (1 if has_diagnostics else 0) + (1 if has_fix else 0)

    exact_best = None
    exact_best_score = (-1, -1)
    subset_best = None
    subset_best_score = (-1, -1)

    for rule in rules:
        rule_metrics = normalize_rule_metrics(rule)
        if not rule_metrics:
            continue

        rule_set = set(rule_metrics)
        if not rule_set.issubset(metric_set):
            continue

        score = (len(rule_set), section_score(rule))

        if rule_set == metric_set:
            if score > exact_best_score:
                exact_best = rule
                exact_best_score = score
        else:
            if score > subset_best_score:
                subset_best = rule
                subset_best_score = score

    if exact_best and exact_best_score[1] >= 2:
        return exact_best

    if subset_best and subset_best_score[1] > exact_best_score[1]:
        return subset_best

    if exact_best:
        return exact_best
    if subset_best:
        return subset_best

    if len(metric_set) == 1:
        only_metric = next(iter(metric_set))
        if only_metric in single_metric_fallback:
            return single_metric_fallback[only_metric]

    return None


def check_trisul_connection(host=TRISUL_HOST, port=TRISUL_PORT, timeout=5):
    """Quick TCP connectivity check to Trisul endpoint before running queries."""
    try:
        socket.create_connection((host, port), timeout=timeout)
        print(f"Connected to {host}:{port}")
        return True
    except Exception as e:
        print(f"Unable to connect to {host}:{port}")
        print(e)
        return False


def connect_trisul():
    """Create and return a connected ZMQ REQ socket for Trisul TRP requests."""
    context = zmq.Context()
    sock = context.socket(zmq.REQ)
    sock.connect(f"tcp://{TRISUL_HOST}:{TRISUL_PORT}")
    return sock


def key_to_ip(key_obj):
    """Convert Trisul hex-key format (AA.BB.CC.DD) to dotted IPv4 if possible."""
    raw_key = str(key_obj.key)
    parts = raw_key.split(".")
    if len(parts) == 4:
        try:
            return ".".join(str(int(p, 16)) for p in parts)
        except Exception:
            pass
    return raw_key


def mk_trp_request(command, data):
    """Build a serialized TRP topper request payload."""
    msg = trp_pb2.Message()
    msg.trp_command = command
    req = msg.counter_group_topper_request
    req.counter_group = str(data["counter_group"])
    req.meter = data["meter"]
    req.maxitems = data["maxitems"]
    getattr(req.time_interval, "from").tv_sec = data["time_interval"]["from"]["tv_sec"]
    req.time_interval.to.tv_sec = data["time_interval"]["to"]["tv_sec"]
    return msg.SerializeToString()


def mk_trp_trend_request(command, data):
    """Build a serialized TRP trend request payload."""
    msg = trp_pb2.Message()
    msg.trp_command = command
    req = msg.topper_trend_request
    req.counter_group = str(data["counter_group"])
    req.meter = data["meter"]
    req.maxitems = data["maxitems"]
    getattr(req.time_interval, "from").tv_sec = data["time_interval"]["from"]["tv_sec"]
    req.time_interval.to.tv_sec = data["time_interval"]["to"]["tv_sec"]
    return msg.SerializeToString()


def unwrap_response(raw_msg):
    """Decode raw protobuf bytes into a trp_pb2.Message object."""
    msg = trp_pb2.Message()
    msg.ParseFromString(raw_msg)
    return msg


def send_zmq_request(req_bytes):
    """Send request bytes to Trisul and return raw response bytes."""
    sock = connect_trisul()
    sock.send(req_bytes)
    msg = sock.recv()
    sock.close()
    return msg


def fetch_meter_summary(group_id, meter, from_ts, to_ts):
    """Fetch aggregate meter series stats for SYS:GROUP_TOTALS within a time window."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_ITEM_REQUEST

    req = msg.counter_item_request
    req.counter_group = str(group_id)
    req.meter = meter
    req.key.key = "SYS:GROUP_TOTALS"
    getattr(req.time_interval, "from").tv_sec = from_ts
    req.time_interval.to.tv_sec = to_ts

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)

    series = []
    for stat_row in resp.counter_item_response.stats:
        if len(stat_row.values) > meter:
            series.append(int(stat_row.values[meter]))

    if not series:
        return None

    return {
        "min": int(min(series)),
        "max": int(max(series)),
        "avg": int(sum(series) / len(series)),
        "latest": int(series[-1]),
        "total": int(sum(series)),
    }


def fetch_counter_group_meta(group_id):
    """Fetch meter type metadata and bucket size for a counter group."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_GROUP_INFO_REQUEST

    req = msg.counter_group_info_request
    req.counter_group = str(group_id)
    req.get_meter_info = True

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)

    meter_types = {}
    topper_bucket_size = 60

    for group in resp.counter_group_info_response.group_details:
        if group.guid == str(group_id):
            topper_bucket_size = int(group.topper_bucket_size) if group.topper_bucket_size else 60
            for meter in group.meters:
                meter_types[int(meter.id)] = int(meter.type)
            break

    return meter_types, topper_bucket_size


def fetch_counter_group_info(group_id):
    """Fetch display labels, meter types, and bucket size for a counter group."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_GROUP_INFO_REQUEST

    req = msg.counter_group_info_request
    req.counter_group = str(group_id)
    req.get_meter_info = True

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)

    meter_labels = {}
    meter_types = {}
    topper_bucket_size = 60

    for group in resp.counter_group_info_response.group_details:
        if group.guid == str(group_id):
            topper_bucket_size = int(group.topper_bucket_size) if group.topper_bucket_size else 60
            for meter in group.meters:
                meter_id = int(meter.id)
                meter_labels[meter_id] = METER_FULL_NAMES.get(meter_id, meter.name)
                meter_types[meter_id] = int(meter.type)
            break

    return meter_labels, meter_types, topper_bucket_size


def fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems=5):
    """Fetch top suspect keys/IPs for one meter in the given time range."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_GROUP_TOPPER_REQUEST

    req = msg.counter_group_topper_request
    req.counter_group = str(group_id)
    req.meter = meter
    req.maxitems = maxitems
    req.resolve_keys = True
    getattr(req.time_interval, "from").tv_sec = from_ts
    req.time_interval.to.tv_sec = to_ts

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)

    results = []
    for key_obj in resp.counter_group_topper_response.keys:
        key_name = str(key_obj.key)
        if not key_name or key_name == "SYS:GROUP_TOTALS":
            continue

        ip = key_to_ip(key_obj)
        metric_value = int(key_obj.metric) if key_obj.HasField("metric") else 0

        results.append({
            "ip": ip,
            "key": key_name,
            "value": metric_value,
        })

        if len(results) >= maxitems:
            break

    return results


def fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts):
    """Fetch per-meter averaged values for a single Trisul key."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_ITEM_REQUEST

    req = msg.counter_item_request
    req.counter_group = str(group_id)
    req.key.key = trisul_key
    req.volumes_only = 0
    getattr(req.time_interval, "from").tv_sec = from_ts
    req.time_interval.to.tv_sec = to_ts

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)

    meter_series = {}
    for stat_row in resp.counter_item_response.stats:
        for meter_id, value in enumerate(stat_row.values):
            meter_series.setdefault(meter_id, []).append(int(value))

    meter_values = {}
    for meter_id, series in meter_series.items():
        if series:
            meter_values[meter_id] = int(sum(series) / len(series))

    return meter_values


def normalize_ip_key(value):
    """Normalize key text to dotted IPv4 when it looks like hex-octet format."""
    key = str(value or "")
    parts = key.split(".")
    if len(parts) == 4:
        try:
            return ".".join(str(int(p, 16)) for p in parts)
        except Exception:
            return key
    return key


def ipv4_to_trisul_key(ip):
    """Convert dotted IPv4 to Trisul hex key format (AA.BB.CC.DD)."""
    text = str(ip or "").strip()
    parts = text.split(".")
    if len(parts) != 4:
        return text
    try:
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return text
        return ".".join(f"{n:02X}" for n in nums)
    except Exception:
        return text


def query_sessions_for_any_ip(any_ip_key, any_ip_readable, from_ts, to_ts, maxitems):
    """Low-level QUERY_SESSIONS request wrapper filtered by any_ip."""
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.QUERY_SESSIONS_REQUEST

    req = msg.query_sessions_request
    req.maxitems = maxitems
    req.resolve_keys = False
    getattr(req.time_interval, "from").tv_sec = from_ts
    req.time_interval.to.tv_sec = to_ts

    if any_ip_readable:
        req.any_ip.readable = any_ip_readable

    raw_resp = send_zmq_request(msg.SerializeToString())
    resp = unwrap_response(raw_resp)
    return list(resp.query_sessions_response.sessions)


def parse_port_key(value):
    """Parse endpoint key values to integer port when possible."""
    text = str(value or "")
    if text.startswith("p-"):
        text = text[2:]
    try:
        return int(text, 16)
    except Exception:
        try:
            return int(text)
        except Exception:
            return None


def endpoint_display_value(key_obj):
    """Return best display value for endpoint key (port/readable/label/raw)."""
    raw = str(getattr(key_obj, "key", "") or "")
    parsed = parse_port_key(raw)
    if parsed is not None:
        return parsed

    readable = str(getattr(key_obj, "readable", "") or "").strip()
    if readable:
        return readable

    label = str(getattr(key_obj, "label", "") or "").strip()
    if label:
        return label

    return raw.lower() if raw else "-"


def key_pretty_label(key_obj):
    """Return preferred key text using readable label fallback chain."""
    readable = str(getattr(key_obj, "readable", "") or "").strip()
    if readable:
        return readable

    label = str(getattr(key_obj, "label", "") or "").strip()
    if label:
        return label

    return normalize_ip_key(getattr(key_obj, "key", ""))


def protocol_display_value(proto_key_obj):
    """Map protocol token/id to readable protocol label."""
    raw = key_pretty_label(proto_key_obj)
    token = str(raw or "").strip().upper()

    proto_map = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "58": "ICMPV6",
        "TCP": "TCP",
        "UDP": "UDP",
        "ICMP": "ICMP",
        "ICMPV6": "ICMPV6",
    }
    return proto_map.get(token, token if token else "-")


def compute_flow_volume(sess):
    """Compute flow volume using payload bytes first, then total bytes fallback."""
    az_payload = int(getattr(sess, "az_payload", 0) or 0)
    za_payload = int(getattr(sess, "za_payload", 0) or 0)
    payload_total = az_payload + za_payload
    if payload_total > 0:
        return payload_total

    az_bytes = int(getattr(sess, "az_bytes", 0) or 0)
    za_bytes = int(getattr(sess, "za_bytes", 0) or 0)
    return az_bytes + za_bytes


def format_ist_timestamp(tv_sec):
    """Convert epoch seconds to IST timestamp string."""
    try:
        ts = int(tv_sec)
    except Exception:
        ts = 0
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(IST_TZ).strftime("%Y-%m-%d %H:%M:%S")


def format_duration_us(total_us):
    """Format microseconds as human-readable seconds+microseconds string."""
    us = max(0, int(total_us or 0))
    sec = us // 1_000_000
    rem_us = us % 1_000_000
    if sec > 0 and rem_us > 0:
        return f"{sec} s {rem_us} us"
    if sec > 0:
        return f"{sec} s"
    return f"0 s {rem_us} us"


def get_geo(ip):
    """Resolve and cache geo/IP provider details with safe fallbacks."""
    ip_text = str(ip or "").strip()

    if not ip_text:
        return {
            "country": "-",
            "state": "-",
            "city": "-",
            "isp": "-",
        }

    # Reuse cached result to avoid repeated external lookups.
    if ip_text in GEO_CACHE:
        return GEO_CACHE[ip_text]

    if ip_text.startswith("SYS:"):
        GEO_CACHE[ip_text] = {
            "country": "-",
            "state": "-",
            "city": "-",
            "isp": "-",
        }
        return GEO_CACHE[ip_text]

    parts = ip_text.split(".")
    if len(parts) != 4:
        GEO_CACHE[ip_text] = {
            "country": "-",
            "state": "-",
            "city": "-",
            "isp": "-",
        }
        return GEO_CACHE[ip_text]

    try:
        if any(int(p) < 0 or int(p) > 255 for p in parts):
            raise ValueError("invalid ipv4")
    except Exception:
        GEO_CACHE[ip_text] = {
            "country": "-",
            "state": "-",
            "city": "-",
            "isp": "-",
        }
        return GEO_CACHE[ip_text]

    try:
        info = get_ip_info(ip_text) or {}
    except Exception:
        info = {}

    geo = {
        "country": str(info.get("country", "-") or "-"),
        "state": str(info.get("region", info.get("state", "-")) or "-"),
        "city": str(info.get("city", "-") or "-"),
        "isp": str(info.get("isp", info.get("org", "-")) or "-"),
    }

    GEO_CACHE[ip_text] = geo
    return geo


def is_same_network(ip1, ip2, subnet_mask="255.255.255.0"):
    """Return True when two IPv4 addresses belong to the same subnet."""
    try:
        ip1_parts = [int(x) for x in str(ip1).split(".")]
        ip2_parts = [int(x) for x in str(ip2).split(".")]
        mask_parts = [int(x) for x in str(subnet_mask).split(".")]

        if len(ip1_parts) != 4 or len(ip2_parts) != 4 or len(mask_parts) != 4:
            return False

        for i in range(4):
            if (ip1_parts[i] & mask_parts[i]) != (ip2_parts[i] & mask_parts[i]):
                return False
        return True
    except Exception:
        return False


def get_infra_for_ip(ip, infra_snapshot):
    """Return infra snapshot with matched route based on LAN/WAN and IP type."""
    if not isinstance(infra_snapshot, dict):
        return None

    vm = infra_snapshot.get("vm", {}) if isinstance(infra_snapshot.get("vm", {}), dict) else {}
    lan_ip = str(vm.get("lan_ip", "") or "").strip()
    wan_ip = str(vm.get("wan_ip", "") or "").strip()

    def with_route(route_name):
        enriched = dict(infra_snapshot)
        enriched["route"] = route_name
        return enriched

    # Strict subnet matches first.
    if lan_ip and is_same_network(ip, lan_ip):
        return with_route("LAN")
    if wan_ip and is_same_network(ip, wan_ip):
        return with_route("WAN")

    return None


def fetch_flows_for_ip(ip, from_ts, to_ts, maxitems=200):
    """Fetch and normalize session flow rows for one IP in the time range."""
    sessions = []
    seen_ids = set()

    candidates = [(None, ip)]

    for any_ip_key, any_ip_readable in candidates:
        try:
            batch = query_sessions_for_any_ip(any_ip_key, any_ip_readable, from_ts, to_ts, maxitems)
        except Exception:
            batch = []

        for sess in batch:
            sid = str(getattr(sess, "session_id", "") or "")
            dedup_key = sid or str(getattr(sess, "session_key", "") or "")
            if dedup_key and dedup_key in seen_ids:
                continue
            if dedup_key:
                seen_ids.add(dedup_key)
            sessions.append(sess)

        if sessions:
            break

    flows = []
    # Build UI/API-ready flow row dictionaries.
    for sess in sessions:
        src_ip = normalize_ip_key(sess.key1A.key)
        dst_ip = normalize_ip_key(sess.key1Z.key)
        src_label = key_pretty_label(sess.key1A)
        dst_label = key_pretty_label(sess.key1Z)
        src_endpoint = endpoint_display_value(sess.key2A)
        dst_endpoint = endpoint_display_value(sess.key2Z)
        protocol = protocol_display_value(sess.protocol)
        volume = compute_flow_volume(sess)
        rtt_us = int(getattr(sess, "setup_rtt", 0) or 0)
        retrans = int(getattr(sess, "retransmissions", 0) or 0)

        start_sec = int(getattr(getattr(sess.time_interval, "from"), "tv_sec", 0) or 0)
        start_usec = int(getattr(getattr(sess.time_interval, "from"), "tv_usec", 0) or 0)
        end_sec = int(getattr(sess.time_interval.to, "tv_sec", 0) or 0)
        end_usec = int(getattr(sess.time_interval.to, "tv_usec", 0) or 0)

        duration_us = max(0, (end_sec - start_sec) * 1_000_000 + (end_usec - start_usec))
        start_time_ist = format_ist_timestamp(start_sec)
        duration = format_duration_us(duration_us)
        probe = str(getattr(sess, "probe_id", "") or "")
        tags = str(getattr(sess, "tags", "") or "")

        if src_ip == ip:
            peer_ip = dst_label
            peer_port = dst_endpoint
        elif dst_ip == ip:
            peer_ip = src_label
            peer_port = src_endpoint
        else:
            peer_ip = dst_label
            peer_port = dst_endpoint

        dst_geo = get_geo(dst_ip)

        flows.append({
            "proto": protocol,
            "src_ip": src_label,
            "src_port": src_endpoint,
            "dst_ip": dst_label,
            "dst_port": dst_endpoint,
            "country": dst_geo["country"],
            "state": dst_geo["state"],
            "city": dst_geo["city"],
            "isp": dst_geo["isp"],
            "volume": volume,
            "rtt_us": rtt_us,
            "retrans": retrans,
            "start_time_ist": start_time_ist,
            "duration": duration,
            "probe": probe,
            "tags": tags,
            "ip": peer_ip,
            "port": peer_port,
        })

    return flows


def rank_problem_flows(flows, top_n=5):
    """Rank flows by severity signals (RTT, retransmissions) and return top N."""
    ranked = sorted(flows, key=lambda x: (x.get("rtt_us", 0), x.get("retrans", 0)), reverse=True)
    return ranked[:top_n]


def get_top_flow_issues(ip, lookback_seconds=3600, maxitems=30, top_n=5):
    """End-to-end helper: fetch, rank, and return top flow issues for one IP."""
    to_ts = int(time.time())
    from_ts = to_ts - lookback_seconds

    flows = fetch_flows_for_ip(ip, from_ts, to_ts, maxitems=maxitems)
    ranked = rank_problem_flows(flows, top_n=top_n)

    return [
        {
            "proto": f["proto"],
            "src_ip": f["src_ip"],
            "src_port": f["src_port"],
            "dst_ip": f["dst_ip"],
            "dst_port": f["dst_port"],
            "country": f["country"],
            "state": f["state"],
            "city": f["city"],
            "isp": f["isp"],
            "volume": f["volume"],
            "ip": f["ip"],
            "port": f["port"],
            "rtt_us": f["rtt_us"],
            "retrans": f["retrans"],
            "start_time_ist": f["start_time_ist"],
            "duration": f["duration"],
            "probe": f["probe"],
            "tags": f["tags"],
        }
        for f in ranked
    ]


def start_ip_flow_api(host="127.0.0.1", port=8080, infra_snapshot=None):
    """Run HTTP API for flow drill-down; optionally attach infra snapshot in response."""
    class IpFlowsHandler(BaseHTTPRequestHandler):
        """HTTP request handler for /api/ip_flows endpoint."""
        def _send_json(self, status_code, payload):
            """Send a JSON HTTP response with CORS headers."""
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            """Serve flow issue data for requested IP."""
            parsed = urlparse(self.path)
            if parsed.path != "/api/ip_flows":
                self._send_json(404, {"error": "not_found"})
                return

            qs = parse_qs(parsed.query)
            ip = (qs.get("ip") or [""])[0].strip()
            include_infra = (qs.get("include_infra") or ["false"])[0].strip().lower() in {"1", "true", "yes"}
            if not ip:
                self._send_json(400, {"error": "ip query parameter is required"})
                return

            try:
                data = get_top_flow_issues(ip)
                if include_infra:
                    ip_infra = get_infra_for_ip(ip, infra_snapshot)
                    self._send_json(200, {
                        "infra": ip_infra or {},
                        "flow_data": data,
                    })
                else:
                    self._send_json(200, data)
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})

    server = HTTPServer((host, port), IpFlowsHandler)
    print(f"Flow API listening on http://{host}:{port}/api/ip_flows?ip=<IP>")
    server.serve_forever()


def start_ip_flow_api_background(host="127.0.0.1", port=8080, infra_snapshot=None):
    """Start API server in a daemon thread and return thread handle."""
    thread = Thread(
        target=start_ip_flow_api,
        kwargs={"host": host, "port": port, "infra_snapshot": infra_snapshot},
        daemon=True,
    )
    thread.start()
    return thread


def format_int(value):
    """Format integer with comma separators."""
    return f"{int(value):,}"


def convert_to_milliseconds(meter_id, value):
    """Format raw meter value using meter-specific units."""
    if meter_id in (0, 1):
        ms_value = value / 1000
        return f"{ms_value:,.2f} ms"
    elif meter_id in (2, 3):
        return f"{int(value):,} pkts"
    elif meter_id in (4, 5):
        return f"{value:,.2f}%"
    else:
        return f"{int(value):,}"


def classify_issue(ip_meters):
    """Classify issue directionality using detected meter set."""
    if INTERNAL_SET.issubset(ip_meters):
        return "INTERNAL ISSUE"
    elif EXTERNAL_SET.issubset(ip_meters):
        return "EXTERNAL ISSUE"
    else:
        has_internal_signal = bool(ip_meters & INTERNAL_UNIQUE_METERS)
        has_external_signal = bool(ip_meters & EXTERNAL_UNIQUE_METERS)

        if has_external_signal and not has_internal_signal:
            return "EXTERNAL ISSUE"
        elif has_internal_signal and not has_external_signal:
            return "INTERNAL ISSUE"
        elif has_internal_signal and has_external_signal:
            return "INTERNAL + EXTERNAL ISSUE"

    return "UNKNOWN"


def fetch_tcp_analyzer_counters(group_id, output_file=None, infra_snapshot=None):
    """Main analyzer pipeline: collect counters, map issues, and emit report/console output."""
    rules = load_rules()

    to_ts = int(time.time())
    from_ts = to_ts - 3600

    meter_results = {}
    meter_summaries = {}

    meter_labels, _meter_types, _topper_bucket_size = fetch_counter_group_info(group_id)

    # Pull topper lists and summary stats for each meter in the selected group.
    for meter in sorted(meter_labels.keys()):
        meter_summaries[meter] = fetch_meter_summary(group_id, meter, from_ts, to_ts)
        meter_results[meter] = fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems=5)

    ranked_ips = []
    for meter, entries in meter_results.items():
        for rank, entry in enumerate(entries, start=1):
            ranked_ips.append({"meter": meter, "rank": rank, "ip": entry["ip"]})

    ip_list = [item["ip"] for item in ranked_ips]
    post_payload = json.dumps({"ips": ip_list}, separators=(",", ":"))
    curl_cmd = (
        "curl -X POST \"http://127.0.0.1:8080/api/ip_flows\" "
        "-H \"Content-Type: application/json\" "
        f"-d '{post_payload}'"
    )

    print(curl_cmd)

    ip_to_meters = {}
    ip_to_meter_values = {}
    suspect_ip_to_key = {}

    for entries in meter_results.values():
        for item in entries:
            suspect_ip_to_key.setdefault(item["ip"], item["key"])

    for ip, trisul_key in suspect_ip_to_key.items():
        all_meter_values = fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts)
        filtered_values = {m: v for m, v in all_meter_values.items() if m in meter_labels}
        ip_to_meter_values[ip] = filtered_values
        ip_to_meters[ip] = {m for m, v in filtered_values.items() if v > 0}

    prefetched_flow_issues = {}
    prefetched_ip_top_values = {}
    prefetched_ip_geo = {}

    if output_file:
        # Do NOT prefetch flows here - this was causing the long delay.
        # Flow data will be loaded only when the user clicks an IP.
        for ip in suspect_ip_to_key:
            prefetched_ip_geo[ip] = get_geo(ip)
            ip_infra = get_infra_for_ip(ip, infra_snapshot)
            meter_items = []
            for meter_id, meter_value in ip_to_meter_values.get(ip, {}).items():
                meter_items.append({
                    "metric": meter_labels.get(meter_id, f"Meter {meter_id}"),
                    "value": convert_to_milliseconds(meter_id, meter_value),
                    "raw": int(meter_value),
                })
            meter_items.sort(key=lambda x: x["raw"], reverse=True)
            prefetched_ip_top_values[ip] = {
                "metrics": meter_items[:5],
                "infra": ip_infra,
            }

    if output_file:
        html_parts = []

        html_parts.append("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TCP Analyzer Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
        }
        .header .timestamp {
            font-size: 14px;
            color: #bdc3c7;
            margin-top: 5px;
        }
        .infra-section {
            background-color: white;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 15px;
        }
        .infra-title {
            margin: 0 0 10px 0;
            color: #2c3e50;
            font-size: 20px;
        }
        .infra-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
        }
        .infra-item {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 10px;
            font-size: 14px;
        }
        .infra-label {
            color: #475569;
            font-weight: 600;
            margin-right: 6px;
        }
        .meter-section {
            background-color: white;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: visible;
        }
        .meter-header {
            background-color: #34495e;
            color: white;
            padding: 15px;
            font-size: 18px;
            font-weight: bold;
        }
        .meter-stats {
            margin-top: 8px;
            font-size: 13px;
            color: #ecf0f1;
        }
        .meter-id {
            background-color: #1abc9c;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 14px;
            margin-right: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        .meter-table {
            table-layout: fixed;
        }
        th {
            background-color: #ecf0f1;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #bdc3c7;
            font-weight: 600;
        }
        th.value-col {
            text-align: right;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        td.value-col {
            text-align: right;
            font-family: 'Courier New', monospace;
        }
        .ip-analysis {
            background-color: #fff9e6;
            padding: 15px;
            margin: 10px;
            border-left: 4px solid #f39c12;
            border-radius: 3px;
        }
        .issues-header {
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }
        .issue-metric {
            margin-left: 20px;
            margin-bottom: 5px;
            color: #555;
        }
        .issue-infra {
            margin: 8px 0 10px 20px;
            color: #2c3e50;
            font-size: 13px;
        }
        .classification {
            background-color: #e74c3c;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            display: inline-block;
            margin: 10px 0;
            font-weight: bold;
        }
        .classification.external {
            background-color: #e67e22;
        }
        .classification.both {
            background-color: #c0392b;
        }
        .rule-box {
            background-color: white;
            border: 1px solid #bdc3c7;
            border-radius: 3px;
            padding: 15px;
            margin-top: 10px;
        }
        .rule-section {
            margin-bottom: 15px;
        }
        .rule-section h4 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .rule-section ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .rule-section li {
            margin-bottom: 5px;
        }
        .no-data {
            padding: 20px;
            text-align: center;
            color: #95a5a6;
            font-style: italic;
        }
        .no-rule {
            color: #7f8c8d;
            font-style: italic;
            margin-top: 10px;
        }
        .ip-link {
            border: none;
            background: transparent;
            color: #1f6feb;
            text-decoration: underline;
            cursor: pointer;
            padding: 0;
            font: inherit;
        }
        .ip-link:hover {
            color: #0b4aa6;
        }
        .flow-details-row td {
            background-color: #f8fbff;
        }
        .flow-details {
            margin: 10px;
            border-left: 4px solid #1f6feb;
            background: #eef5ff;
            border-radius: 4px;
            padding: 12px;
            overflow: visible;
        }
        .flow-title {
            font-weight: 700;
            color: #1a3a63;
            margin-bottom: 8px;
        }
        .flow-content {
            color: #294b77;
            font-size: 14px;
        }
        .flow-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 6px;
        }
        .flow-table-wrap {
            display: block;
            overflow-x: auto;
            overflow-y: hidden;
            margin-top: 6px;
        }
        .flow-table th,
        .flow-table td {
            border-bottom: 1px solid #d6e4f8;
            padding: 8px;
            text-align: left;
            font-size: 13px;
            vertical-align: top;
            white-space: nowrap;
        }
        .flow-table th {
            background: #dceafb;
            color: #1b3658;
        }
        .flow-muted {
            color: #64748b;
            font-style: italic;
        }
    </style>
</head>
<body>
""")

        report_time = datetime.fromtimestamp(to_ts).strftime("%Y-%m-%d %H:%M:%S")
        from_time = datetime.fromtimestamp(from_ts).strftime("%Y-%m-%d %H:%M:%S")
        to_time = datetime.fromtimestamp(to_ts).strftime("%Y-%m-%d %H:%M:%S")

        html_parts.append(f"""
    <div class="header">
        <h1>TCP Analyzer Top Counters Report</h1>
        <div class="timestamp">Generated: {report_time} | Time Range: Last 1 hour (from {from_time} to {to_time})</div>
    </div>
""")

        infra = infra_snapshot or {}
        vm_info = infra.get("vm", {}) if isinstance(infra, dict) else {}
        cpu_info = infra.get("cpu", {}) if isinstance(infra, dict) else {}
        ram_info = infra.get("ram", {}) if isinstance(infra, dict) else {}

        html_parts.append(f"""
    <div class="infra-section">
        <h2 class="infra-title">System Resources</h2>
        <div class="infra-grid">
            <div class="infra-item"><span class="infra-label">CPU Usage:</span>{escape(f"{_to_float(cpu_info.get('latest_pct', 0.0)):.2f}%")}</div>
            <div class="infra-item"><span class="infra-label">RAM Usage:</span>{escape(f"{_to_float(ram_info.get('latest_pct', 0.0)):.2f}%")}</div>
            <div class="infra-item"><span class="infra-label">RAM:</span>{escape(str(vm_info.get("ram", "-")))}</div>
            <div class="infra-item"><span class="infra-label">Disk:</span>{escape(str(vm_info.get("disk", "-")))}</div>
        </div>
    </div>
""")

        # Render per-meter sections and issue breakdown rows.
        for meter, label in sorted(meter_labels.items()):
            results = meter_results.get(meter, [])
            summary = meter_summaries.get(meter)
            meter_stats_html = ""

            if summary:
                meter_stats_html = f"""
            <div class="meter-stats">
                Min: {escape(convert_to_milliseconds(meter, summary["min"]))} |
                Max: {escape(convert_to_milliseconds(meter, summary["max"]))} |
                Avg: {escape(convert_to_milliseconds(meter, summary["avg"]))} |
                Latest: {escape(convert_to_milliseconds(meter, summary["latest"]))}
            </div>
"""

            html_parts.append(f"""
    <div class="meter-section">
        <div class="meter-header">
            <span class="meter-id">{meter}</span>{label}{meter_stats_html}
        </div>
""")

            if results:
                html_parts.append("""
        <table class="meter-table">
            <thead>
                <tr>
                    <th style="width: 10%;">Rank</th>
                    <th style="width: 90%;">IP Address</th>
                </tr>
            </thead>
            <tbody>
""")

                for idx, entry in enumerate(results, start=1):
                    ip = entry["ip"]
                    safe_ip = escape(ip, quote=True)
                    display_ip = escape(ip)
                    flow_row_id = f"flow-row-{meter}-{idx}"
                    ip_infra = get_infra_for_ip(ip, infra_snapshot)

                    html_parts.append(f"""
                <tr>
                    <td>{idx}</td>
                    <td><button class="ip-link" data-ip="{safe_ip}" data-target="{flow_row_id}">{display_ip}</button></td>
                </tr>
                <tr id="{flow_row_id}" class="flow-details-row" style="display:none;">
                    <td colspan="3">
                        <div class="flow-details" data-loaded="0">
                            <div class="flow-title">Top 5 Flow Issues</div>
                            <div class="flow-content flow-muted">Click the IP to load flow issues.</div>
                        </div>
                    </td>
                </tr>
""")

                    ip_meters = ip_to_meters.get(ip, set())
                    if ip_meters:
                        html_parts.append("""
                <tr>
                    <td colspan="3">
                        <div class="ip-analysis">
                            <div class="issues-header">🔍 Issues Detected:</div>
""")

                        if ip_infra:
                            infra_vm = ip_infra.get("vm", {}) if isinstance(ip_infra.get("vm", {}), dict) else {}
                            infra_route = str(ip_infra.get("route", "") or "")
                            infra_hostname = str(infra_vm.get("hostname", "") or "")
                            html_parts.append(f"""
                            <div class="issue-infra"><strong>Infra Route:</strong> {escape(infra_route)} | <strong>Hostname:</strong> {escape(infra_hostname)}</div>
""")

                        metrics_set = set()
                        for m in sorted(ip_meters):
                            label_name = meter_labels.get(m, f"Meter {m}")
                            meter_value = ip_to_meter_values[ip].get(m, 0)
                            converted_value = convert_to_milliseconds(m, meter_value)
                            html_parts.append(f"""
                            <div class="issue-metric">• {escape(label_name)}: <strong>{escape(converted_value)}</strong></div>
""")
                            if m in METER_TO_METRIC:
                                metrics_set.add(METER_TO_METRIC[m])

                        metrics = sorted(list(metrics_set))
                        classification = classify_issue(ip_meters)
                        class_type = "external" if "EXTERNAL" in classification else ("both" if "+" in classification else "internal")

                        html_parts.append(f"""
                            <div class="classification {class_type}">🎯 {escape(classification)}</div>
""")

                        rule = find_matching_rule(metrics, rules)
                        if rule:
                            html_parts.append("""
                            <div class="rule-box">
""")

                            if rule.get("problem"):
                                html_parts.append(f"""
                                <div class="rule-section">
                                    <h4>📋 Problem:</h4>
                                    <p>{escape(rule["problem"])}</p>
                                </div>
""")

                            if rule.get("diagnostics"):
                                html_parts.append("""
                                <div class="rule-section">
                                    <h4>🔧 Diagnostics:</h4>
                                    <ul>
""")
                                for d in rule["diagnostics"]:
                                    if d.strip():
                                        html_parts.append(f"                                        <li>{escape(d)}</li>\n")
                                html_parts.append("""
                                    </ul>
                                </div>
""")

                            if rule.get("fix"):
                                html_parts.append("""
                                <div class="rule-section">
                                    <h4>✅ Fix:</h4>
                                    <ul>
""")
                                for f in rule["fix"]:
                                    if f.strip():
                                        html_parts.append(f"                                        <li>{escape(f)}</li>\n")
                                html_parts.append("""
                                    </ul>
                                </div>
""")

                            html_parts.append("""
                            </div>
""")
                        else:
                            html_parts.append("""
                            <div class="no-rule">ℹ️ No specific diagnostic rule found for this combination</div>
""")

                        html_parts.append("""
                        </div>
                    </td>
                </tr>
""")

                html_parts.append("""
            </tbody>
        </table>
""")
            else:
                html_parts.append("""
        <div class="no-data">No data available for this meter</div>
""")

            html_parts.append("""
    </div>
""")

        prefetched_flow_issues_json = json.dumps(prefetched_flow_issues)
        prefetched_ip_top_values_json = json.dumps(prefetched_ip_top_values)
        prefetched_ip_geo_json = json.dumps(prefetched_ip_geo)

        html_parts.append("""
    <script>
    (function () {
""")
        html_parts.append(f"    var PREFETCH_FLOW_ISSUES = {prefetched_flow_issues_json};\n")
        html_parts.append(f"    var PREFETCH_IP_TOP_VALUES = {prefetched_ip_top_values_json};\n")
        html_parts.append(f"    var PREFETCH_IP_GEO = {prefetched_ip_geo_json};\n")
        html_parts.append("""
    function escapeHtml(text) {
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/\\"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function getApiBase() {
        if (window.location.protocol === "http:" || window.location.protocol === "https:") {
            return window.location.origin;
        }
        return "http://127.0.0.1:8080";
    }

    function formatPercent(value) {
        if (value == null || value === "") {
            return "";
        }
        return String(value) + '%';
    }

    function renderFlowTable(rows, ip) {
        var obj = PREFETCH_IP_TOP_VALUES[ip] || {};
        var infra = obj.infra || null;
        var infraVm = (infra && infra.vm) ? infra.vm : {};
        var infraCpu = (infra && infra.cpu) ? infra.cpu : {};
        var infraRam = (infra && infra.ram) ? infra.ram : {};
        var infraHtml = '';

        if (infra && infra.route) {
            infraHtml =
                '<div class="flow-content"><strong>System Resource:</strong><br>' +
                'Route: ' + escapeHtml(infra.route) + '<br>' +
                'Hostname: ' + escapeHtml(infraVm.hostname || '') + '<br>' +
                'LAN IP: ' + escapeHtml(infraVm.lan_ip || '') + '<br>' +
                'WAN IP: ' + escapeHtml(infraVm.wan_ip || '') + '<br>' +
                'CPU Usage: ' + escapeHtml(formatPercent(infraCpu.latest_pct)) + '<br>' +
                'RAM Usage: ' + escapeHtml(formatPercent(infraRam.latest_pct)) + '<br>' +
                'RAM: ' + escapeHtml(infraVm.ram || '') + '<br>' +
                'Disk: ' + escapeHtml(infraVm.disk || '') + '<br>' +
                '</div>';
        }

        if (!rows || rows.length === 0) {
            var fallback = obj.metrics || [];
            var geo = PREFETCH_IP_GEO[ip] || {};
            var geoHtml = '<div class="flow-content"><strong>Selected IP Geo:</strong> Country: ' +
                escapeHtml(geo.country || '-') + ', State: ' +
                escapeHtml(geo.state || '-') + ', City: ' +
                escapeHtml(geo.city || '-') + ', ISP: ' +
                escapeHtml(geo.isp || '-') + '</div>';

            if (!fallback.length) {
                return infraHtml + geoHtml + '<div class="flow-content flow-muted">No flow rows available for this IP in the selected window.</div>';
            }

            var fallbackHtml = [
                infraHtml,
                geoHtml,
                '<div class="flow-table-wrap">',
                '<table class="flow-table">',
                '<thead><tr><th>#</th><th>Metric</th><th>Value</th></tr></thead>',
                '<tbody>'
            ];

            fallback.forEach(function (r, i) {
                fallbackHtml.push(
                    '<tr>' +
                    '<td>' + (i + 1) + '</td>' +
                    '<td>' + escapeHtml(r.metric || "") + '</td>' +
                    '<td>' + escapeHtml(r.value || "") + '</td>' +
                    '</tr>'
                );
            });

            fallbackHtml.push('</tbody></table></div>');
            return fallbackHtml.join('');
        }

        var html = [
            infraHtml,
            '<div class="flow-table-wrap">',
            '<table class="flow-table">',
            '<thead><tr><th>Proto</th><th>IP</th><th>Port</th><th>IP</th><th>Port</th><th>Country</th><th>State</th><th>City</th><th>ISP</th><th>Volume</th><th>RTT(us)</th><th>Retrans</th><th>Start Time IST</th><th>Duration</th><th>Probe</th><th>Tags</th></tr></thead>',
            '<tbody>'
        ];

        rows.forEach(function (r) {
            var geoCountry = r.country || "-";
            var geoState = r.state || "-";
            var geoCity = r.city || "-";
            var geoIsp = r.isp || "-";
            var rowSrcIp = String(r.src_ip || "");
            var rowDstIp = String(r.dst_ip || "");
            var clickedGeo = PREFETCH_IP_GEO[ip] || {};

            if (geoCountry === "-" && geoState === "-" && geoCity === "-" && geoIsp === "-") {
                if (rowSrcIp === ip || rowDstIp === ip) {
                    geoCountry = clickedGeo.country || "-";
                    geoState = clickedGeo.state || "-";
                    geoCity = clickedGeo.city || "-";
                    geoIsp = clickedGeo.isp || "-";
                }
            }

            html.push(
                '<tr>' +
                '<td>' + escapeHtml(r.proto || "") + '</td>' +
                '<td>' + escapeHtml(r.src_ip || "") + '</td>' +
                '<td>' + escapeHtml(r.src_port == null ? "-" : String(r.src_port)) + '</td>' +
                '<td>' + escapeHtml(r.dst_ip || "") + '</td>' +
                '<td>' + escapeHtml(r.dst_port == null ? "-" : String(r.dst_port)) + '</td>' +
                '<td>' + escapeHtml(geoCountry) + '</td>' +
                '<td>' + escapeHtml(geoState) + '</td>' +
                '<td>' + escapeHtml(geoCity) + '</td>' +
                '<td>' + escapeHtml(geoIsp) + '</td>' +
                '<td>' + escapeHtml(String(r.volume || 0)) + '</td>' +
                '<td>' + escapeHtml(String(r.rtt_us || 0)) + '</td>' +
                '<td>' + escapeHtml(String(r.retrans || 0)) + '</td>' +
                '<td>' + escapeHtml(r.start_time_ist || "") + '</td>' +
                '<td>' + escapeHtml(r.duration || "") + '</td>' +
                '<td>' + escapeHtml(r.probe || "") + '</td>' +
                '<td>' + escapeHtml(r.tags || "") + '</td>' +
                '</tr>'
            );
        });

        html.push('</tbody></table></div>');
        return html.join('');
    }

    function ensureFlowLoaded(button, panel) {
        if (panel.dataset.loaded === "1") {
            return;
        }

        var ip = button.dataset.ip;
        var content = panel.querySelector(".flow-content");

        if (Object.prototype.hasOwnProperty.call(PREFETCH_FLOW_ISSUES, ip)) {
            content.outerHTML = renderFlowTable(PREFETCH_FLOW_ISSUES[ip], ip);
            panel.dataset.loaded = "1";
            return;
        }

        var apiBase = getApiBase();
        var url = apiBase + "/api/ip_flows?ip=" + encodeURIComponent(ip);
        content.textContent = "Loading flow issues...";

        fetch(url)
            .then(function (resp) {
                if (!resp.ok) {
                    throw new Error("HTTP " + resp.status);
                }
                return resp.json();
            })
            .then(function (data) {
                content.outerHTML = renderFlowTable(data, ip);
                panel.dataset.loaded = "1";
            })
            .catch(function (err) {
                content.textContent = "Failed to load flow issues. Ensure API mode is running (--mode serve_api). Error: " + err.message;
            });
    }

    document.querySelectorAll(".ip-link").forEach(function (button) {
        button.addEventListener("click", function () {
            var targetId = button.dataset.target;
            var row = document.getElementById(targetId);
            if (!row) {
                return;
            }

            var isHidden = row.style.display === "none";
            row.style.display = isHidden ? "" : "none";

            if (isHidden) {
                var panel = row.querySelector(".flow-details");
                if (panel) {
                    ensureFlowLoaded(button, panel);
                }
            }
        });
    });
})();
</script>
</body>
</html>
""")

        # Final HTML write to disk.
        html_content = "".join(html_parts)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"Report saved to: {output_file}")
        print(f"  Time Range: Last 1 hour (from {datetime.fromtimestamp(from_ts).strftime('%Y-%m-%d %H:%M:%S')})")
        print(f"              to {datetime.fromtimestamp(to_ts).strftime('%Y-%m-%d %H:%M:%S')})")

    else:
        internal_ips = set()

        for meter, label in sorted(meter_labels.items()):
            results = meter_results.get(meter, [])

            for idx, entry in enumerate(results, start=1):
                ip = entry["ip"]
                ip_meters = ip_to_meters.get(ip, set())

                if not ip_meters:
                    continue

                classification = classify_issue(ip_meters)
                if classification == "INTERNAL ISSUE":
                    internal_ips.add(ip)

        print("\n" + "=" * 50)
        print("INTERNAL IPs ONLY")
        print("=" * 50)

        if internal_ips:
            for ip in sorted(internal_ips):
                print(ip)
        else:
            print("No INTERNAL IPs found")


if __name__ == "__main__":
    # CLI entrypoint: parse args, load infra snapshot, then run selected mode.
    parser = argparse.ArgumentParser(description="Trisul TCP analyzer and flow issue drill-down")
    parser.add_argument("--mode", choices=["report", "ip_flows", "serve_api", "report_with_api"], default="report")
    parser.add_argument("--ip", help="IP for flow drill-down (required for ip_flows mode)")
    parser.add_argument("--host", default="127.0.0.1", help="API bind host for serve_api mode")
    parser.add_argument("--port", type=int, default=8080, help="API bind port for serve_api mode")
    parser.add_argument("--vm-json", default=DEFAULT_VM_JSON, help="Path to VM metadata JSON")
    parser.add_argument("--ram-json", default=DEFAULT_RAM_JSON, help="Path to RAM resources JSON")
    parser.add_argument("--cpu-json", default=DEFAULT_CPU_JSON, help="Path to CPU resources JSON")
    args = parser.parse_args()

    infra_snapshot = load_infra_snapshot(args.vm_json, args.ram_json, args.cpu_json)

    if check_trisul_connection(TRISUL_HOST, TRISUL_PORT):
        try:
            if args.mode == "serve_api":
                start_ip_flow_api(host=args.host, port=args.port, infra_snapshot=infra_snapshot)
            elif args.mode == "report_with_api":
                start_ip_flow_api_background(host=args.host, port=args.port, infra_snapshot=infra_snapshot)
                print("\nFetching TCP Analyzer counters...\n")
                group_guid = "{E45623ED-744C-4053-1401-84C72EE49D3B}"
                html_output = r"C:\sri\trisulauto\tcp-report.html"
                fetch_tcp_analyzer_counters(group_guid, output_file=html_output, infra_snapshot=infra_snapshot)
                print(f"\nAPI is running at http://{args.host}:{args.port}. Keep this terminal open while viewing the report.")
                print("Press Ctrl+C to stop API server.\n")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("Stopped API server.")
            elif args.mode == "ip_flows":
                if not args.ip:
                    raise ValueError("--ip is required for --mode ip_flows")
                print(json.dumps(get_top_flow_issues(args.ip), indent=2))
            else:
                print("\nFetching TCP Analyzer counters...\n")
                group_guid = "{E45623ED-744C-4053-1401-84C72EE49D3B}"
                html_output = r"C:\sri\trisulauto\tcp-report.html"
                fetch_tcp_analyzer_counters(group_guid, output_file=html_output, infra_snapshot=infra_snapshot)
        except Exception as exc:
            print(f"Failed to resolve/query TCP analyzer counters: {exc}")
    else:
        print("Skipping API query because connection failed.")