import requests

def get_ip_info(ip):

    url = f"http://ip-api.com/json/{ip}"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":

            return {
                "country": data.get("country", "-"),
                "region": data.get("regionName", "-"),
                "city": data.get("city", "-"),
                "isp": data.get("isp", "-")
            }

        else:
            return {
                "country": "-",
                "region": "-",
                "city": "-",
                "isp": "-"
            }

    except Exception:
        return {
            "country": "-",
            "region": "-",
            "city": "-",
            "isp": "-"
        }


if __name__ == "__main__":

    ip_address = "92.122.63.32"
    info = get_ip_info(ip_address)

    print("IP:", ip_address)
    print("Country:", info["country"])
    print("State:", info["region"])
    print("City:", info["city"])
    print("ISP:", info["isp"])