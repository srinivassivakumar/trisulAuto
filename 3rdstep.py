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
    9: "Cardinality 1",
    10: "Cardinality 2",
}


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


def send_message(msg):
    sock = connect_trisul()
    sock.send(msg.SerializeToString())
    raw_resp = sock.recv()
    sock.close()

    resp = trp_pb2.Message()
    resp.ParseFromString(raw_resp)
    return resp


def get_counter_group_info(group_id=None, get_meter_info=True):
    msg = trp_pb2.Message()
    msg.trp_command = trp_pb2.Message.COUNTER_GROUP_INFO_REQUEST

    req = msg.counter_group_info_request
    if group_id is not None:
        req.counter_group = str(group_id)
    req.get_meter_info = get_meter_info

    resp = send_message(msg)

    if resp.HasField("error_response"):
        raise RuntimeError(resp.error_response.error_message)

    return resp.counter_group_info_response


def key_to_ip(key_obj):
    """Convert TRP key to a human-readable IP when possible.

    Typical raw TRP key format seen for IPv4 is hex bytes separated by dots,
    e.g. "67.AE.6B.3C" => "103.174.107.60".
    """
    raw_key = str(key_obj.key)
    readable = str(getattr(key_obj, "readable", "") or "")

    # If Trisul already provides a readable IPv4 string, use it directly.
    if readable.count(".") == 3 and all(part.isdigit() for part in readable.split(".")):
        return readable

    # Convert dotted hex bytes to dotted decimal IPv4.
    parts = raw_key.split(".")
    if len(parts) == 4:
        try:
            octets = [str(int(part, 16)) for part in parts]
            return ".".join(octets)
        except ValueError:
            pass

    # Keep special/system keys or unknown formats as-is.
    return raw_key


def mk_trp_request(command, data):
    msg = trp_pb2.Message()

    msg.trp_command = command

    req = msg.counter_group_topper_request
    req.counter_group = str(data["counter_group"])
    req.meter = data["meter"]
    req.maxitems = data["maxitems"]

    if "time_interval" in data:
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


def resolve_tcp_analyzer_group_id(target_hint="tcp"):
    info = get_counter_group_info(group_id=None, get_meter_info=True)
    groups = list(info.group_details)

    if not groups:
        raise RuntimeError("No counter groups returned")

    hint = target_hint.lower()
    matches = [g for g in groups if hint in g.name.lower()]

    if matches:
        selected = matches[0]
        return selected.guid, selected.name, selected.meters

    selected = groups[0]
    return selected.guid, selected.name, selected.meters


def fetch_tcp_analyzer_counters(group_id, from_ts=0, to_ts=0, meter_mapping=None):
    if from_ts == 0 and to_ts == 0:
        to_ts = int(time.time())
        from_ts = to_ts - 3600

    print("=" * 72)
    print("TCP Analyzer Top Counters")
    print("=" * 72)
    print(f"Counter Group : {group_id}")
    print(f"From         : {datetime.fromtimestamp(from_ts)}")
    print(f"To           : {datetime.fromtimestamp(to_ts)}")
    print("=" * 72)

    if meter_mapping is None:
        meter_mapping = DEFAULT_TCP_METER_LABELS.copy()
    else:
        meter_mapping = {
            meter_id: f"{DEFAULT_TCP_METER_LABELS.get(meter_id, f'Meter {meter_id}')} ({meter_name})" if meter_name else DEFAULT_TCP_METER_LABELS.get(meter_id, f"Meter {meter_id}")
            for meter_id, meter_name in meter_mapping.items()
        }

    for meter, name in sorted(meter_mapping.items(), key=lambda x: x[0]):
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

        print(f"\n[{meter}] {name}")
        print("-" * 72)

        if resp.HasField("error_response"):
            print(f"TRP error: {resp.error_response.error_message}")
            continue

        keys = resp.counter_group_topper_response.keys

        if not keys:
            print("No data in selected time range")
            continue

        print(f"{'Rank':<6}{'IP Address':<26}{'Value':>16}")
        print(f"{'-'*6}{'-'*26}{'-'*16}")

        count = 0
        rank = 1

        for key in keys:
            raw_key = str(key.key)

            if raw_key == "SYS:GROUP_TOTALS":
                continue

            ip = key_to_ip(key)
            metric_value = format_int(key.metric)

            print(f"{rank:<6}{ip:<26}{metric_value:>16}")

            rank += 1
            count += 1

            if count == 5:
                break

        if count == 0:
            print("No top IP keys in selected time range")


if __name__ == "__main__":

    if check_trisul_connection(TRISUL_HOST, TRISUL_PORT):

        print("\nFetching TCP Analyzer counters...\n")

        try:
            group_guid, group_name, meters = resolve_tcp_analyzer_group_id("tcp")

            print(f"Resolved counter group: {group_name} ({group_guid})")

            dynamic_meter_mapping = {m.id: m.name for m in meters} if meters else None

            if dynamic_meter_mapping:
                print(f"Meters discovered from Trisul: {len(dynamic_meter_mapping)}")

            fetch_tcp_analyzer_counters(
                group_guid,
                from_ts=0,
                to_ts=0,
                meter_mapping=dynamic_meter_mapping,
            )

        except Exception as exc:
            print(f"Failed to resolve/query TCP analyzer counters: {exc}")

    else:
        print("Skipping API query because connection failed.")