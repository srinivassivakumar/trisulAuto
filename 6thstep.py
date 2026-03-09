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


# ============================================================================
# METER LABEL MAPPING: Human-readable names for each TCP quality meter
# ============================================================================
# Maps meter IDs (0-10) to descriptive labels for operators
# These represent different network quality metrics tracked by Trisul
DEFAULT_TCP_METER_LABELS = {
    0: "Avg Latency Internal",       # Meter 0: Average latency on internal (LAN/DC) paths
    1: "Avg Latency External",       # Meter 1: Average latency on external (WAN/Internet) paths
    2: "Retrans Internal",           # Meter 2: Count of retransmitted packets on internal paths
    3: "Retrans External",           # Meter 3: Count of retransmitted packets on external paths
    4: "Retrans Rate Internal",      # Meter 4: Percentage of retransmitted packets on internal paths
    5: "Retrans Rate External",      # Meter 5: Percentage of retransmitted packets on external paths
    6: "Poor Quality Flows",         # Meter 6: Count of flows with poor quality (both internal/external)
    7: "Timeouts",                   # Meter 7: Count of connection timeout events (mostly internal)
    8: "Unidirectional",             # Meter 8: Count of unidirectional flows (anomaly indicator)
}


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
    with open(RULE_FILE, "r") as f:
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
    # Convert metrics list to set for subset comparison
    metric_set = set(metrics)
    
    # Iterate through each rule in rules database
    for rule in rules:
        # Retrieve the metrics array from rule (Empty if not defined)
        rule_metrics = rule.get("metrics", [])
        
        # Skip rules with no metrics defined
        if not rule_metrics:
            continue
        
        # Check if all metrics in the rule are present in detected metrics
        # Subset check means rule can match with additional detected metrics
        if set(rule_metrics).issubset(metric_set):
            # Return first matching rule (by insertion order)
            return rule
    
    # Return None if no matching rule found in database
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
# FUNCTION: fetch_tcp_analyzer_counters(group_id)
# PURPOSE: Main orchestration function
#   1. Query Trisul for top counters across all meters
#   2. Convert hex IP keys to dotted decimal notation
#   3. Build IP-to-meters index for classification
#   4. Display results with issue classification and matching rules
# PARAMS: group_id = GUID of TCP Analyzer counter group in Trisul
# ============================================================================
def fetch_tcp_analyzer_counters(group_id):
    # Load rules database once (reused for all IPs processed)
    rules = load_rules()
    
    # PHASE 1: Calculate time window for query (last 1 hour)
    # Get current UTC timestamp
    to_ts = int(time.time())
    # Start time is 1 hour (3600 seconds) before now
    from_ts = to_ts - 3600
    
    # Dictionary to store results: {meter_id: [{"ip": ip, "value": metric_value}, ...]}
    meter_results = {}
    
    # PHASE 2: Query each meter (0-10) from Trisul for top-5 IPs
    for meter in DEFAULT_TCP_METER_LABELS.keys():
        # Build data dictionary for TRP request
        data = {
            "counter_group": group_id,           # Which group to query (TCP Analyzer)
            "meter": meter,                      # Which metric to fetch (0-10)
            "maxitems": 5,                       # Limit to top-5 results
            "time_interval": {
                "from": {"tv_sec": from_ts},     # Start time in seconds since epoch
                "to": {"tv_sec": to_ts},         # End time in seconds since epoch
            },
        }
        
        # Build serialized TRP request message
        req = mk_trp_request(trp_pb2.Message.COUNTER_GROUP_TOPPER_REQUEST, data)
        
        # Send request to Trisul and get binary response
        raw_resp = send_zmq_request(req)
        
        # Deserialize binary response into protobuf Message object
        resp = unwrap_response(raw_resp)
        
        # Extract list of counter keys (IPs) from response
        keys = resp.counter_group_topper_response.keys
        
        # List to accumulate results for this meter
        results = []
        
        # Process each returned key (IP address result)
        for key in keys:
            # Skip system totals key (not a real endpoint)
            if str(key.key) == "SYS:GROUP_TOTALS":
                continue
            
            # Convert hex-format IP key to dotted decimal notation
            ip = key_to_ip(key)
            
            # Gather IP and metric value into result entry
            results.append({
                "ip": ip,                        # IP address (converted from hex)
                "value": key.metric              # Metric value (count, latency, etc.)
            })
        
        # Store all results for this meter in dictionary
        meter_results[meter] = results
    
    # PHASE 3: Build IP-to-meters index for classification and value lookup
    # Dictionary: {ip_address: set(meter_ids where this IP appeared)}
    ip_to_meters = {}
    
    # Dictionary: {ip_address: {meter_id: value}} for displaying values per issue
    ip_to_meter_values = {}
    
    # Iterate through all meters and their results
    for m_id, entries in meter_results.items():
        # For each IP that appeared in this meter's results
        for item in entries:
            ip = item["ip"]
            value = item["value"]
            
            # Create IP entry if new
            if ip not in ip_to_meters:
                ip_to_meters[ip] = set()
                ip_to_meter_values[ip] = {}
            
            # Add this meter to the IP's set of detected meters
            ip_to_meters[ip].add(m_id)
            
            # Store the value for this meter and IP
            ip_to_meter_values[ip][m_id] = value
    
    # PHASE 4: Display results with formatting and analysis
    # Print header banner
    print("=" * 72)
    print("TCP Analyzer Top Counters")
    print("=" * 72)
    
    # Iterate through all meters in order (0-10) for display
    for meter, label in DEFAULT_TCP_METER_LABELS.items():
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
                
                # List to collect metric codes for rule lookup
                metrics = []
                
                # Show friendly names AND VALUES of all meters this IP appeared in
                for m in sorted(ip_meters):
                    label_name = DEFAULT_TCP_METER_LABELS[m]
                    meter_value = ip_to_meter_values[ip][m]
                    # Display meter name with its value formatted with commas
                    print(f"      - {label_name}: {format_int(meter_value)}")
                    
                    # Collect metric abbreviation for rule matching
                    metrics.append(METER_TO_METRIC[m])
                
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
            
            # STEP 3: Query Trisul and display results with analysis
            fetch_tcp_analyzer_counters(group_guid)
        
        # Catch any errors during query/processing
        except Exception as exc:
            print(f"Failed to resolve/query TCP analyzer counters: {exc}")
    
    else:
        # Connection to Trisul failed - cannot proceed with queries
        print("Skipping API query because connection failed.")
