import socket


def check_trisul_connection(host="10.193.2.9", port=12001, timeout=5):
    try:
        socket.create_connection((host, port), timeout=timeout)
        print(f"Connected to {host}:{port}")
    except Exception as e:
        print(f"Unable to connect to {host}:{port}")
        print(e)


check_trisul_connection()