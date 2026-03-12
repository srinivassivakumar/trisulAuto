# Import standard library modules for socket operations, time handling, JSON parsing, and datetime utilities
import socket
import time
import json
from datetime import datetime

# Import ZeroMQ for network message passing and Protocol Buffers for TRP message serialization
import zmq
import trp_pb2


# ============================================================================
# CONFIGURATION SECTION: Trisul Server Connection Settings
# ============================================================================

# IP address of the Trisul Analytics server running TRP protocol
TRISUL_HOST = "10.193.2.9"

# Port number where Trisul listens for TRP (Trisul Remote Protocol) connections
TRISUL_PORT = 12001

# File path to the network issue rules JSON database with diagnostics and fixes
RULE_FILE = r"C:\sri\trisulauto\network_issue_rules.json"


# Meter labels are discovered dynamically from Trisul via COUNTER_GROUP_INFO_REQUEST.


# ============================================================================
# METRIC ABBREVIATION MAPPING: Short codes for rule matching
# ============================================================================
# Maps meter IDs to metric abbreviations used in the rules database
# Used to look up matching rules based on detected metrics
METER_TO_METRIC = {
    0: "LAT",   # Meter 0 → LAT (Latency metric, internal)
    1: "LAT",   # Meter 1 → LAT (Latency metric, external)
    2: "RPKT",  # Meter 2 → RPKT (Retransmitted packets, internal)
    3: "RPKT",  # Meter 3 → RPKT (Retransmitted packets, external)
    4: "R%",    # Meter 4 → R% (Retransmission rate %, internal)
    5: "R%",    # Meter 5 → R% (Retransmission rate %, external)
    6: "PQF",   # Meter 6 → PQF (Poor quality flows)
    7: "TO",    # Meter 7 → TO (Timeouts)
    8: "UNI",   # Meter 8 → UNI (Unidirectional flows)
}


# ============================================================================
# CLASSIFICATION LOGIC CONSTANTS: Sets of meter IDs for issue detection
# ============================================================================

# Meters that indicate INTERNAL network path issues when present
# Includes: Lat Int, Retrans Int, Retrans% Int, Poor Quality, Timeouts, Unidirectional
INTERNAL_SET = {0, 2, 4, 6, 7, 8}

# Meters that indicate EXTERNAL network path issues when present
# Includes: Lat Ext, Retrans Ext, Retrans% Ext, Poor Quality, Unidirectional
EXTERNAL_SET = {1, 3, 5, 6, 8}

# Meters that can appear in BOTH internal and external issue sets
# These are not decisive on their own for classification
SHARED_METERS = {6, 8}

# Meters unique to INTERNAL issues (not in EXTERNAL_SET)
# Used for relaxed classification when full set not present
INTERNAL_UNIQUE_METERS = INTERNAL_SET - SHARED_METERS

# Meters unique to EXTERNAL issues (not in INTERNAL_SET)
# Used for relaxed classification when full set not present
EXTERNAL_UNIQUE_METERS = EXTERNAL_SET - SHARED_METERS

# ============================================================================
# FUNCTION: load_rules()
# PURPOSE: Load network issue rules from JSON file for diagnostics lookup
# ============================================================================
def load_rules():
    # Open the rules JSON file in read mode
    # utf-8-sig handles files with or without UTF-8 BOM safely
    with open(RULE_FILE, "r", encoding="utf-8-sig") as f:
        # Parse JSON content into Python dict/list structure
        data = json.load(f)
    # Return only the "rules" array, which contains rule objects with problem/fix info
    return data["rules"]

# ============================================================================
# FUNCTION: find_matching_rule(metrics, rules)
# PURPOSE: Find diagnostic rule matching detected metrics
# PARAMS: metrics = list of metric codes (e.g. ["LAT", "RPKT"])
#         rules = loaded rules array from JSON
# RETURNS: Matching rule object with problem/diagnostics/fix, or None
# ============================================================================
def find_matching_rule(metrics, rules):
    # Valid metric tokens used by rule issue names and metric arrays
    known_metrics = {"LAT", "RPKT", "R%", "PQF", "TO", "UNI"}
    metric_set = {m for m in metrics if m in known_metrics}

    # Fallback guidance when only one metric is present and no good rule matches
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
        # Keep only valid explicit metrics from JSON
        explicit = [m for m in rule.get("metrics", []) if m in known_metrics]

        # Infer expected metrics from issue_name like "LAT + RPKT + TO"
        issue_name = rule.get("issue_name", "")
        inferred = []
        if isinstance(issue_name, str) and "+" in issue_name:
            for token in issue_name.split("+"):
                t = token.strip()
                if t in known_metrics and t not in inferred:
                    inferred.append(t)

        # Prefer inferred metrics when explicit metrics are missing or inconsistent
        if inferred and (not explicit or set(explicit) != set(inferred) or len(explicit) != len(inferred)):
            return inferred
        return explicit

    def section_score(rule):
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

        # Prefer most specific and richest match
        score = (len(rule_set), section_score(rule))

        if rule_set == metric_set:
            if score > exact_best_score:
                exact_best = rule
                exact_best_score = score
        else:
            if score > subset_best_score:
                subset_best = rule
                subset_best_score = score

    # Prefer exact match when it has useful context (problem/diagnostics/fix).
    # If exact match is sparse (fix-only), prefer a richer subset rule.
    if exact_best and exact_best_score[1] >= 2:
        return exact_best

    if subset_best and subset_best_score[1] > exact_best_score[1]:
        return subset_best

    if exact_best:
        return exact_best
    if subset_best:
        return subset_best

    # Return fallback for known single-metric cases
    if len(metric_set) == 1:
        only_metric = next(iter(metric_set))
        if only_metric in single_metric_fallback:
            return single_metric_fallback[only_metric]

    return None

# ============================================================================
# FUNCTION: check_trisul_connection(host, port, timeout)
# PURPOSE: Verify that Trisul server is reachable on network before querying
# RETURNS: True if connection successful, False otherwise
# ============================================================================
def check_trisul_connection(host=TRISUL_HOST, port=TRISUL_PORT, timeout=5):
    # Try to create a socket connection to Trisul host:port
    try:
        # Attempt to connect using TCP sockets with specified timeout
        socket.create_connection((host, port), timeout=timeout)
        
        # Print success message if connection established
        print(f"Connected to {host}:{port}")
        
        # Return True to indicate connection successful
        return True
    
    # Catch any connection failures (host unreachable, timeout, port closed, etc.)
    except Exception as e:
        # Print error message with host/port details
        print(f"Unable to connect to {host}:{port}")
        
        # Print actual exception details for debugging
        print(e)
        
        # Return False to indicate connection failed
        return False

# ============================================================================
# FUNCTION: connect_trisul()
# PURPOSE: Establish ZeroMQ connection to Trisul TRP protocol server
# RETURNS: Connected ZMQ socket ready for request/response communication
# ============================================================================
def connect_trisul():
    # Create a ZeroMQ context (factory for creating sockets)
    context = zmq.Context()
    
    # Create a REQ (request) socket type for request/response pattern
    # REQ sockets send request, wait for exactly one response, then continue
    sock = context.socket(zmq.REQ)
    
    # Connect socket to Trisul server using TCP protocol
    # Format: tcp://hostname:port
    sock.connect(f"tcp://{TRISUL_HOST}:{TRISUL_PORT}")
    
    # Return connected socket for use in sending requests
    return sock

# ============================================================================
# FUNCTION: key_to_ip(key_obj)
# PURPOSE: Convert hex-format IP key to human-readable dotted decimal notation
# EXAMPLE: "67.AE.6B.3C" (hex bytes) → "103.174.107.60" (decimal IPv4)
# ============================================================================
def key_to_ip(key_obj):
    # Convert key object to string representation
    raw_key = str(key_obj.key)
    
    # Split key by dot separator to extract individual hex octets
    parts = raw_key.split(".")
    
    # Check if we have exactly 4 octets (valid IPv4 format)
    if len(parts) == 4:
        try:
            # Convert each hex octet to decimal and join with dots
            # int(p, 16) parses hex string p as base-16 integer
            return ".".join(str(int(p, 16)) for p in parts)
        
        # If conversion fails (invalid hex), fall through to return raw key
        except:
            pass
    
    # Return raw key string if not 4-part hex format or conversion failed
    # This preserves special keys like "SYS:GROUP_TOTALS"
    return raw_key

# ============================================================================
# FUNCTION: mk_trp_request(command, data)
# PURPOSE: Build serialized TRP (Trisul Remote Protocol) message for sending
# PARAMS: command = Message type (e.g. COUNTER_GROUP_TOPPER_REQUEST)
#         data = Dictionary with counter_group, meter, maxitems, time_interval
# RETURNS: Serialized byte string ready to send via ZMQ socket
# ============================================================================
def mk_trp_request(command, data):
    # Create a new TRP Message object (protobuf message)
    msg = trp_pb2.Message()
    
    # Set the command type field (tells Trisul what kind of request this is)
    msg.trp_command = command
    
    # Get reference to embedded counter_group_topper_request sub-message
    req = msg.counter_group_topper_request
    
    # Set counter group GUID (identifies which metric group to query)
    # Example: "{E45623ED-744C-4053-1401-84C72EE49D3B}" for TCP Analyzer
    req.counter_group = str(data["counter_group"])
    
    # Set meter ID (0-10) specifying which TCP quality metric to fetch
    req.meter = data["meter"]
    
    # Set maximum number of results to return (e.g., 5 for top-5)
    req.maxitems = data["maxitems"]
    
    # Set start time (UTC seconds since epoch) for query time window
    getattr(req.time_interval, "from").tv_sec = data["time_interval"]["from"]["tv_sec"]
    
    # Set end time (UTC seconds since epoch) for query time window
    req.time_interval.to.tv_sec = data["time_interval"]["to"]["tv_sec"]
    
    # Serialize the message to byte string (binary format for transmission)
    return msg.SerializeToString()

# ============================================================================
# FUNCTION: mk_trp_trend_request(command, data)
# PURPOSE: Build serialized TRP message for Trend API requests
# PARAMS: command = Message type (e.g. TOPPER_TREND_REQUEST)
#         data = Dictionary with counter_group, meter, maxitems, time_interval
# RETURNS: Serialized byte string ready to send via ZMQ socket
# NOTE: Trend requests return time-slice metric arrays instead of cumulative values
# ============================================================================
def mk_trp_trend_request(command, data):
    # Create a new TRP Message object (protobuf message)
    msg = trp_pb2.Message()
    
    # Set the command type field (tells Trisul this is a trend request)
    msg.trp_command = command
    
    # Get reference to embedded topper_trend_request sub-message
    req = msg.topper_trend_request
    
    # Set counter group GUID (identifies which metric group to query)
    # Example: "{E45623ED-744C-4053-1401-84C72EE49D3B}" for TCP Analyzer
    req.counter_group = str(data["counter_group"])
    
    # Set meter ID (0-10) specifying which TCP quality metric to fetch
    req.meter = data["meter"]
    
    # Set maximum number of results to return (e.g., 5 for top-5)
    req.maxitems = data["maxitems"]
    
    # Set start time (UTC seconds since epoch) for query time window
    getattr(req.time_interval, "from").tv_sec = data["time_interval"]["from"]["tv_sec"]
    
    # Set end time (UTC seconds since epoch) for query time window
    req.time_interval.to.tv_sec = data["time_interval"]["to"]["tv_sec"]
    
    # Serialize the message to byte string (binary format for transmission)
    return msg.SerializeToString()

# ============================================================================
# FUNCTION: unwrap_response(raw_msg)
# PURPOSE: Deserialize binary TRP response into protobuf Message object
# PARAMS: raw_msg = Byte string received from Trisul server
# RETURNS: Deserialized Message object with response data
# ============================================================================
def unwrap_response(raw_msg):
    # Create empty TRP Message object to receive deserialized data
    msg = trp_pb2.Message()
    
    # Parse binary byte string into the protobuf message structure
    # This populates msg fields based on binary data from server response
    msg.ParseFromString(raw_msg)
    
    # Return populated message object
    return msg

# ============================================================================
# FUNCTION: send_zmq_request(req_bytes)
# PURPOSE: Send serialized TRP request to Trisul and receive response
# PARAMS: req_bytes = Serialized request message (byte string)
# RETURNS: Raw byte string response from Trisul server
# ============================================================================
def send_zmq_request(req_bytes):
    # Establish ZeroMQ connection to Trisul server
    sock = connect_trisul()
    
    # Send serialized request message to Trisul
    # ZMQ REQ socket sends and waits for response
    sock.send(req_bytes)
    
    # Receive response message from Trisul (blocks until response arrives)
    msg = sock.recv()
    
    # Close socket to clean up connection resources
    sock.close()
    
    # Return raw response byte string for deserialization
    return msg

# ============================================================================
# FUNCTION: fetch_meter_summary(group_id, meter, from_ts, to_ts)
# PURPOSE: Retrieve aggregate meter stats from SYS:GROUP_TOTALS for a time range
# RETURNS: dict with min/max/avg/latest/total, or None if unavailable
# ============================================================================
def fetch_meter_summary(group_id, meter, from_ts, to_ts):
    # Build Counter Item request for SYS:GROUP_TOTALS aggregate key
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

    # CounterItemResponse.stats is a list of StatsArray rows.
    # Each row has values across meters; use index == meter.
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

# ============================================================================
# FUNCTION: fetch_counter_group_meta(group_id)
# PURPOSE: Retrieve meter type metadata and topper bucket size for normalization
# RETURNS: (meter_type_map, topper_bucket_size_seconds)
# ============================================================================
def fetch_counter_group_meta(group_id):
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

# ============================================================================
# FUNCTION: fetch_counter_group_info(group_id)
# PURPOSE: Dynamically fetch meter labels/types and topper bucket size
# RETURNS: (meter_labels, meter_types, topper_bucket_size_seconds)
# ============================================================================
def fetch_counter_group_info(group_id):
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
                meter_labels[meter_id] = meter.name
                meter_types[meter_id] = int(meter.type)
            break

    return meter_labels, meter_types, topper_bucket_size


# ============================================================================
# FUNCTION: fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems)
# PURPOSE: Fetch top keys for a meter using Counter Group Topper API
# RETURNS: list of dicts with dotted IP, raw key, and toplist metric value
# ============================================================================
def fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems=5):
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


# ============================================================================
# FUNCTION: fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts)
# PURPOSE: Fetch full meter profile for one key using Counter Item API
# RETURNS: {meter_id: avg_value_across_interval}
# ============================================================================
def fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts):
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

# ============================================================================
# FUNCTION: format_int(value)
# PURPOSE: Format integer with comma thousands separator for readability
# EXAMPLE: 1785398 → "1,785,398"
# ============================================================================
def format_int(value):
    # Convert value to int, format with comma thousands separator
    # :, format spec adds commas every 3 digits
    return f"{int(value):,}"

# ============================================================================
# FUNCTION: classify_issue(ip_meters)
# PURPOSE: Classify network issue as INTERNAL, EXTERNAL, or BOTH
# PARAMS: ip_meters = Set of meter IDs where this IP appeared in results
# RETURNS: Classification string describing issue type
# ============================================================================
def classify_issue(ip_meters):
    # TIER 1: Strict classification - check if all required meters present
    
    # If ALL meters in INTERNAL_SET detected, definitely an INTERNAL issue
    if INTERNAL_SET.issubset(ip_meters):
        return "INTERNAL ISSUE"
    
    # If ALL meters in EXTERNAL_SET detected, definitely an EXTERNAL issue
    elif EXTERNAL_SET.issubset(ip_meters):
        return "EXTERNAL ISSUE"
    
    # TIER 2: Relaxed classification - check for unique meter indicators
    else:
        # Check if any INTERNAL-unique meters present (meters only in INTERNAL_SET)
        has_internal_signal = bool(ip_meters & INTERNAL_UNIQUE_METERS)
        
        # Check if any EXTERNAL-unique meters present (meters only in EXTERNAL_SET)
        has_external_signal = bool(ip_meters & EXTERNAL_UNIQUE_METERS)
        
        # If external signal only, classify as EXTERNAL
        if has_external_signal and not has_internal_signal:
            return "EXTERNAL ISSUE"
        
        # If internal signal only, classify as INTERNAL
        elif has_internal_signal and not has_external_signal:
            return "INTERNAL ISSUE"
        
        # If both signals present, both paths affected
        elif has_internal_signal and has_external_signal:
            return "INTERNAL + EXTERNAL ISSUE"
    
    # Fallback if no signals match (should not reach in normal operation)
    return "UNKNOWN"

# ============================================================================
# FUNCTION: fetch_tcp_analyzer_counters(group_id, output_file=None)
# PURPOSE: Main orchestration function
#   1. Query Trisul for top counters across all meters
#   2. Convert hex IP keys to dotted decimal notation
#   3. Build IP-to-meters index for classification
#   4. Display results with issue classification and matching rules
#   5. Optionally save results to HTML file
# PARAMS: group_id = GUID of TCP Analyzer counter group in Trisul
#         output_file = Optional path to save HTML report
# ============================================================================
def fetch_tcp_analyzer_counters(group_id, output_file=None):
    # Load rules database once (reused for all IPs processed)
    rules = load_rules()
    
    # PHASE 1: Calculate time window for query (last 1 hour)
    # Get current UTC timestamp
    to_ts = int(time.time())
    # Start time is 1 hour (3600 seconds) before now
    from_ts = to_ts - 3600
    
    # Dictionary to store topper results: {meter_id: [{"ip": ip, "key": key, "value": toplist_metric}, ...]}
    meter_results = {}

    # Dictionary to store meter-level aggregate stats from SYS:GROUP_TOTALS
    meter_summaries = {}

    # Retrieve meter labels/types dynamically once for all calculations
    meter_labels, _meter_types, _topper_bucket_size = fetch_counter_group_info(group_id)

    # PHASE 2: Query each discovered meter from Trisul for top-5 keys
    for meter in sorted(meter_labels.keys()):
        # Fetch meter-level aggregate stats for header display
        meter_summaries[meter] = fetch_meter_summary(group_id, meter, from_ts, to_ts)

        # Use Counter Group Topper to discover suspect keys/IPs for this meter
        meter_results[meter] = fetch_topper_keys(group_id, meter, from_ts, to_ts, maxitems=5)

    # PHASE 3: Pull full Counter Item meter profile for each unique suspect IP
    # Dictionary: {ip_address: set(meter_ids where this IP has non-zero values)}
    ip_to_meters = {}

    # Dictionary: {ip_address: {meter_id: value}} for displaying values per issue
    ip_to_meter_values = {}

    # Keep one raw trisul key per dotted IP so we can query Counter Item
    suspect_ip_to_key = {}
    for entries in meter_results.values():
        for item in entries:
            suspect_ip_to_key.setdefault(item["ip"], item["key"])

    for ip, trisul_key in suspect_ip_to_key.items():
        all_meter_values = fetch_counter_item_all_meters(group_id, trisul_key, from_ts, to_ts)

        # Keep only meters known for this counter-group
        filtered_values = {m: v for m, v in all_meter_values.items() if m in meter_labels}
        ip_to_meter_values[ip] = filtered_values
        ip_to_meters[ip] = {m for m, v in filtered_values.items() if v > 0}
    
    # PHASE 4: Generate output (HTML or console)
    # Determine if HTML output is requested
    if output_file:
        # Build HTML content
        html_parts = []
        
        # HTML header with styling
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
        .meter-section {
            background-color: white;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
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
    </style>
</head>
<body>
""")
        
        # Header with title and timestamp
        report_time = datetime.fromtimestamp(to_ts).strftime('%Y-%m-%d %H:%M:%S')
        from_time = datetime.fromtimestamp(from_ts).strftime('%Y-%m-%d %H:%M:%S')
        to_time = datetime.fromtimestamp(to_ts).strftime('%Y-%m-%d %H:%M:%S')
        html_parts.append(f"""
    <div class="header">
        <h1>TCP Analyzer Top Counters Report</h1>
        <div class="timestamp">Generated: {report_time} | Time Range: Last 1 hour (from {from_time} to {to_time})</div>
    </div>
""")
        
        # Iterate through all dynamically discovered meters for HTML generation
        for meter, label in sorted(meter_labels.items()):
            results = meter_results.get(meter, [])
            summary = meter_summaries.get(meter)
            
            # Meter section header
            meter_stats_html = ""
            if summary:
                meter_stats_html = (
                    f"<div class=\"meter-stats\">"
                    f"Meter Aggregate Avg: <strong>{format_int(summary['avg'])}</strong> | "
                    f"Latest: <strong>{format_int(summary['latest'])}</strong> | "
                    f"Min: <strong>{format_int(summary['min'])}</strong> | "
                    f"Max: <strong>{format_int(summary['max'])}</strong>"
                    f"</div>"
                )

            html_parts.append(f"""
    <div class="meter-section">
        <div class="meter-header">
            <span class="meter-id">{meter}</span>{label}{meter_stats_html}
        </div>
""")
            
            if results:
                # Create table with results
                html_parts.append("""
        <table>
            <thead>
                <tr>
                    <th style="width: 10%;">Rank</th>
                    <th style="width: 45%;">IP Address</th>
                    <th class="value-col" style="width: 45%;">Value</th>
                </tr>
            </thead>
            <tbody>
""")
                
                # Add each result row
                for idx, entry in enumerate(results, start=1):
                    ip = entry["ip"]
                    value = entry["value"]
                    
                    html_parts.append(f"""
                <tr>
                    <td>{idx}</td>
                    <td>{ip}</td>
                    <td class="value-col">{format_int(value)}</td>
                </tr>
""")
                    
                    # Add IP analysis if issues detected
                    ip_meters = ip_to_meters.get(ip, set())
                    if ip_meters:
                        html_parts.append("""
                <tr>
                    <td colspan="3">
                        <div class="ip-analysis">
                            <div class="issues-header">🔍 Issues Detected:</div>
""")
                        
                        # List all detected metrics with values
                        # Use set to collect unique metrics (avoid duplicates when same IP appears in multiple meters mapping to same metric)
                        metrics_set = set()
                        for m in sorted(ip_meters):
                            label_name = meter_labels.get(m, f"Meter {m}")
                            meter_value = ip_to_meter_values[ip].get(m, 0)
                            html_parts.append(f"""
                            <div class="issue-metric">• {label_name} (IP): <strong>{format_int(meter_value)}</strong></div>
""")
                            # Add known metric aliases to rule-engine input
                            if m in METER_TO_METRIC:
                                metrics_set.add(METER_TO_METRIC[m])
                        
                        # Convert set to sorted list for consistent matching
                        metrics = sorted(list(metrics_set))
                        
                        # Add classification
                        classification = classify_issue(ip_meters)
                        class_type = "external" if "EXTERNAL" in classification else ("both" if "+" in classification else "internal")
                        html_parts.append(f"""
                            <div class="classification {class_type}">🎯 {classification}</div>
""")
                        
                        # Find and display matching rule
                        rule = find_matching_rule(metrics, rules)
                        if rule:
                            html_parts.append("""
                            <div class="rule-box">
""")
                            
                            # Problem section
                            if rule.get("problem"):
                                html_parts.append(f"""
                                <div class="rule-section">
                                    <h4>📋 Problem:</h4>
                                    <p>{rule['problem']}</p>
                                </div>
""")
                            
                            # Diagnostics section
                            if rule.get("diagnostics"):
                                html_parts.append("""
                                <div class="rule-section">
                                    <h4>🔧 Diagnostics:</h4>
                                    <ul>
""")
                                for d in rule["diagnostics"]:
                                    if d.strip():
                                        html_parts.append(f"                                        <li>{d}</li>\n")
                                html_parts.append("""
                                    </ul>
                                </div>
""")
                            
                            # Fix section
                            if rule.get("fix"):
                                html_parts.append("""
                                <div class="rule-section">
                                    <h4>✅ Fix:</h4>
                                    <ul>
""")
                                for f in rule["fix"]:
                                    if f.strip():
                                        html_parts.append(f"                                        <li>{f}</li>\n")
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
        
        # HTML footer
        html_parts.append("""
</body>
</html>
""")
        
        # Write HTML to file
        html_content = "".join(html_parts)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"✓ Report saved to: {output_file}")
        print(f"  Time Range: Last 1 hour (from {datetime.fromtimestamp(from_ts).strftime('%Y-%m-%d %H:%M:%S')})")
        print(f"              to {datetime.fromtimestamp(to_ts).strftime('%Y-%m-%d %H:%M:%S')})")
    
    else:
        # Original console output
        print("=" * 72)
        print("TCP Analyzer Top Counters")
        print("=" * 72)
        
        # Iterate through all dynamically discovered meters for display
        for meter, label in sorted(meter_labels.items()):
            # Print meter header with ID and friendly name
            print(f"\n[{meter}] {label}")
            print("-" * 72)
            
            # Print column headers for results table
            print(f"{'Rank':<6}{'IP Address':<30}{'Value':>10}")
            print("-" * 48)
            
            # Get results for this meter from previously fetched data
            results = meter_results.get(meter, [])
            
            # Iterate through each result with rank number (1, 2, 3, etc.)
            for idx, entry in enumerate(results, start=1):
                ip = entry["ip"]
                value = entry["value"]
                
                # Print rank | IP | formatted value with commas
                print(f"{idx:<6}{ip:<30}{format_int(value):>10}")
                
                # Get all meters where this IP appeared
                ip_meters = ip_to_meters.get(ip, set())
                
                # If IP detected in any meters, show analysis/issues
                if ip_meters:
                    # Header for issues section
                    print("      issues detected")
                    
                    # Use set to collect unique metric codes for rule lookup (avoid duplicates)
                    metrics_set = set()
                    
                    # Show friendly names AND VALUES of all meters this IP appeared in
                    for m in sorted(ip_meters):
                        label_name = meter_labels.get(m, f"Meter {m}")
                        meter_value = ip_to_meter_values[ip].get(m, 0)
                        # Display meter name with its value formatted with commas
                        print(f"      - {label_name}: {format_int(meter_value)}")
                        
                        # Collect unique metric abbreviations for rule matching
                        if m in METER_TO_METRIC:
                            metrics_set.add(METER_TO_METRIC[m])
                    
                    # Convert set to sorted list for consistent matching
                    metrics = sorted(list(metrics_set))
                    
                    # Classify the issue as INTERNAL, EXTERNAL, or BOTH
                    classification = classify_issue(ip_meters)
                    print(f"      >>> {classification}")
                    
                    # Look for matching rule in rules database based on metrics
                    rule = find_matching_rule(metrics, rules)
                    
                    # If matching rule found, display problem/diagnostics/fix
                    if rule:
                        # Display problem description if present in rule
                        if rule.get("problem"):
                            print("\n      Problem:")
                            print(f"      {rule['problem']}")
                        
                        # Display diagnostic checklist if present in rule
                        if rule.get("diagnostics"):
                            print("\n      Diagnostics:")
                            for d in rule["diagnostics"]:
                                # Only print non-empty diagnostic items
                                if d.strip():
                                    print(f"      - {d}")
                        
                        # Display fix steps if present in rule
                        if rule.get("fix"):
                            print("\n      Fix:")
                            for f in rule["fix"]:
                                # Only print non-empty fix steps
                                if f.strip():
                                    print(f"      - {f}")
                    else:
                        # If no matching rule found, notify user
                        print("\n      (No specific diagnostic rule found for this combination)")
                    
                    # Add blank line after each IP's analysis for readability
                    print()
            
            # If no data for this meter in time window, show message
            if not results:
                print("No data")
            
            # Add visual separator between meters for readability
            print()


# ============================================================================
# MAIN EXECUTION: Entry point when script is run directly
# ============================================================================
if __name__ == "__main__":
    # STEP 1: Verify Trisul server is reachable before attempting queries
    if check_trisul_connection(TRISUL_HOST, TRISUL_PORT):
        # Connection successful, proceed with data fetch
        
        print("\nFetching TCP Analyzer counters...\n")
        
        try:
            # STEP 2: Define the counter group GUID for TCP Analyzer
            # This GUID is specific to the TCP quality metrics group
            group_guid = "{E45623ED-744C-4053-1401-84C72EE49D3B}"
            
            # STEP 3: Define HTML output file path
            html_output = r"C:\sri\trisulauto\tcp-report.html"
            
            # STEP 4: Query Trisul and save results to HTML file
            fetch_tcp_analyzer_counters(group_guid, output_file=html_output)
        
        # Catch any errors during query/processing
        except Exception as exc:
            print(f"Failed to resolve/query TCP analyzer counters: {exc}")
    
    else:
        # Connection to Trisul failed - cannot proceed with queries
        print("Skipping API query because connection failed.")
