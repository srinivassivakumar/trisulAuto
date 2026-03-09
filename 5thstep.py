import socket
import time
from datetime import datetime

import zmq
import trp_pb2


TRISUL_HOST = "10.193.2.9"
TRISUL_PORT = 12001


DEFAULT_TCP_METER_LABELS = {
    0: "Avg Latency Internal",
    1: "Avg Latency External",
    2: "Retrans Internal",
    3: "Retrans External",
    4: "Retrans Rate Internal",
    5: "Retrans Rate External",
    6: "Poor Quality Flows",
    7: "Timeouts",
    8: "Unidirectional",
}


INTERNAL_SET = {0, 2, 4, 6, 7, 8}
EXTERNAL_SET = {1, 3, 5, 6, 8}

# Shared meters (seen in both internal and external patterns) are not decisive alone.
SHARED_METERS = {6, 8}
INTERNAL_UNIQUE_METERS = INTERNAL_SET - SHARED_METERS  # 0,2,4,7
EXTERNAL_UNIQUE_METERS = EXTERNAL_SET - SHARED_METERS  # 1,3,5


def check_trisul_connection(host="10.193.2.9", port=12001, timeout=5):
    try:
        socket.create_connection((host, port), timeout=timeout)
        print(f"Connected to {host}:{port}")
        return True
    except Exception as e:
        print(f"Unable to connect to {host}:{port}")
        print(e)
        return False


def connect_trisul():
    context = zmq.Context()
    sock = context.socket(zmq.REQ)
    sock.connect(f"tcp://{TRISUL_HOST}:{TRISUL_PORT}")
    return sock


def key_to_ip(key_obj):
    raw_key = str(key_obj.key)
    parts = raw_key.split(".")

    if len(parts) == 4:
        try:
            return ".".join(str(int(p, 16)) for p in parts)
        except:
            pass

    return raw_key


def mk_trp_request(command, data):
    msg = trp_pb2.Message()

    msg.trp_command = command

    req = msg.counter_group_topper_request
    req.counter_group = str(data["counter_group"])
    req.meter = data["meter"]
    req.maxitems = data["maxitems"]

    getattr(req.time_interval, "from").tv_sec = data["time_interval"]["from"]["tv_sec"]
    req.time_interval.to.tv_sec = data["time_interval"]["to"]["tv_sec"]

    return msg.SerializeToString()


def unwrap_response(raw_msg):
    msg = trp_pb2.Message()
    msg.ParseFromString(raw_msg)
    return msg


def send_zmq_request(req_bytes):
    sock = connect_trisul()
    sock.send(req_bytes)
    msg = sock.recv()
    sock.close()
    return msg


def format_int(value):
    return f"{int(value):,}"


def fetch_tcp_analyzer_counters(group_id):

    to_ts = int(time.time())
    from_ts = to_ts - 3600

    meter_results = {}

    # FIRST PASS: collect results
    for meter in DEFAULT_TCP_METER_LABELS.keys():

        data = {
            "counter_group": group_id,
            "meter": meter,
            "maxitems": 5,
            "time_interval": {
                "from": {"tv_sec": from_ts},
                "to": {"tv_sec": to_ts},
            },
        }

        req = mk_trp_request(trp_pb2.Message.COUNTER_GROUP_TOPPER_REQUEST, data)

        raw_resp = send_zmq_request(req)
        resp = unwrap_response(raw_resp)

        keys = resp.counter_group_topper_response.keys

        results = []

        for key in keys:

            if str(key.key) == "SYS:GROUP_TOTALS":
                continue

            ip = key_to_ip(key)

            results.append({
                "ip": ip,
                "value": key.metric
            })

        meter_results[meter] = results

    # Build ip_to_meters map after meter_results is populated.
    ip_to_meters = {}
    for m_id, entries in meter_results.items():
        for item in entries:
            ip = item["ip"]
            if ip not in ip_to_meters:
                ip_to_meters[ip] = set()
            ip_to_meters[ip].add(m_id)

    # SECOND PASS: print results + classification

    print("=" * 72)
    print("TCP Analyzer Top Counters")
    print("=" * 72)

    for meter, label in DEFAULT_TCP_METER_LABELS.items():

        print(f"\n[{meter}] {label}")
        print("-" * 72)

        print(f"{'Rank':<6}{'IP Address':<30}{'Value':>10}")
        print("-" * 48)

        results = meter_results.get(meter, [])

        for idx, entry in enumerate(results, start=1):

            ip = entry["ip"]
            value = entry["value"]

            print(f"{idx:<6}{ip:<30}{format_int(value):>10}")

            ip_meters = ip_to_meters.get(ip, set())

            if ip_meters:

                print("      issues detected")

                for m in sorted(ip_meters):
                    print(f"      - {DEFAULT_TCP_METER_LABELS[m]}")

                # Classification
                if INTERNAL_SET.issubset(ip_meters):
                    print("      >>> INTERNAL ISSUE")

                elif EXTERNAL_SET.issubset(ip_meters):
                    print("      >>> EXTERNAL ISSUE")

                else:
                    has_internal_signal = bool(ip_meters & INTERNAL_UNIQUE_METERS)
                    has_external_signal = bool(ip_meters & EXTERNAL_UNIQUE_METERS)

                    # Relaxed rule: any unique meter is enough for classification.
                    if has_external_signal and not has_internal_signal:
                        print("      >>> EXTERNAL ISSUE")
                    elif has_internal_signal and not has_external_signal:
                        print("      >>> INTERNAL ISSUE")
                    elif has_internal_signal and has_external_signal:
                        print("      >>> INTERNAL + EXTERNAL ISSUE")

        if not results:
            print("No data")


if __name__ == "__main__":

    if check_trisul_connection(TRISUL_HOST, TRISUL_PORT):

        print("\nFetching TCP Analyzer counters...\n")

        try:

            # Hardcoded TCP Analyzer GUID (same you showed earlier)
            group_guid = "{E45623ED-744C-4053-1401-84C72EE49D3B}"

            fetch_tcp_analyzer_counters(group_guid)

        except Exception as exc:

            print(f"Failed to resolve/query TCP analyzer counters: {exc}")

    else:

        print("Skipping API query because connection failed.")