import requests
import json

URL = "https://dev-admin-console.zybisys.com/api/admin-api/vm-performance/103.174.107.238?from=1773815400000&to=1773816300000"
HEADERS = {"X-SECRET-KEY": "A0tziuB02IrdIS"}


def fetch_data():
    try:
        response = requests.get(URL, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching data:", e)
        return None


def pretty_print(data):
    print(json.dumps(data, indent=4))


def extract_metrics(data):
    print("\nExtracted Metrics:\n")

    for entry in data.get("message", []):
        time = entry.get("cpu_load", {}).get("time", "N/A")
        cpu = entry.get("cpu", {}).get("percent_used", "N/A")
        ram = entry.get("ram", {}).get("percent_used", "N/A")
        tcp = entry.get("tcp_connection", {}).get("established", "N/A")

        print(f"Time: {time} | CPU: {cpu}% | RAM: {ram}% | TCP: {tcp}")


def main():
    data = fetch_data()

    if not data:
        return

    print("\nFull API Response:\n")
    pretty_print(data)

    extract_metrics(data)


if __name__ == "__main__":
    main()