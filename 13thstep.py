import requests
import json
import time

BASE_URL = "https://dev-admin-console.zybisys.com/api/admin-api/vm-performance"
HEADERS = {"X-SECRET-KEY": "A0tziuB02IrdIS"}


def get_time_range():
    to_ts = int(time.time() * 1000)
    from_ts = to_ts - (60 * 60 * 1000)
    return from_ts, to_ts


def fetch_data(ip):
    from_ts, to_ts = get_time_range()
    url = f"{BASE_URL}/{ip}?from={from_ts}&to={to_ts}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching data:", e)
        return None


def pretty_print(data):
    print(json.dumps(data, indent=4))


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_metrics(data):
    cpu_values = []
    ram_values = []
    tcp_values = []

    for entry in data.get("message", []):
        cpu = entry.get("cpu", {}).get("percent_used", "N/A")
        ram = entry.get("ram", {}).get("percent_used", "N/A")
        tcp = entry.get("tcp_connection", {}).get("established", "N/A")

        cpu_values.append(to_float(cpu))
        ram_values.append(to_float(ram))
        tcp_values.append(to_float(tcp))

    if cpu_values:
        avg_cpu = sum(cpu_values) / len(cpu_values)
        avg_ram = sum(ram_values) / len(ram_values)
        avg_tcp = sum(tcp_values) / len(tcp_values)

        return {
            "cpu": round(avg_cpu, 2),
            "ram": round(avg_ram, 2),
            "tcp": round(avg_tcp, 2),
        }

    return {"cpu": 0, "ram": 0, "tcp": 0}


def fetch_vm_metrics(ip):
    data = fetch_data(ip)
    if not data:
        return {"cpu": 0, "ram": 0, "tcp": 0}
    return extract_metrics(data)


def main():
    ip = "103.174.107.238"
    metrics = fetch_vm_metrics(ip)
    print("\nAveraged Metrics:\n")
    print(f"CPU Average: {metrics['cpu']:.2f}%")
    print(f"RAM Average: {metrics['ram']:.2f}%")
    print(f"TCP Established Average: {metrics['tcp']:.2f}")


if __name__ == "__main__":
    main()