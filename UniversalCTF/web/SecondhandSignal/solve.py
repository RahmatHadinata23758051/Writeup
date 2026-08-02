import re
import json
import html
import hashlib
import requests
from bs4 import BeautifulSoup

BASE = "https://http-01kz0z2fmxh3jg8mvzsvdbzn32.u-ctf-ctf-7001b39a.urc.tf"

requests.packages.urllib3.disable_warnings()
sess = requests.Session()


def get(path):
    return sess.get(BASE + path, verify=False, timeout=15).text


def post(action, data):
    return sess.post(
        BASE + f"/api.php?action={action}",
        data=data,
        verify=False,
        timeout=15,
    )


def hash_to_scalar(q, *parts):
    raw = "|".join(map(str, parts)).encode()
    digest = hashlib.sha256(raw).digest()
    value = int.from_bytes(digest, "big") % q
    return value or 1


def parse_config():
    html_page = get("/")
    m = re.search(r"window\.RelayAppConfig\s*=\s*(\{.*?\});", html_page, re.S)
    if not m:
        raise RuntimeError("RelayAppConfig not found")

    cfg = json.loads(m.group(1))
    p = int(cfg["crypto"]["p"])
    q = int(cfg["crypto"]["q"])
    g = int(cfg["crypto"]["g"])
    return p, q, g


def get_public_key(username, p, q):
    page = get(f"/index.php?page=profile&user={username}")
    nums = [int(x) for x in re.findall(r"\b\d{40,}\b", page)]
    nums = [x for x in nums if x not in (p, q)]

    if not nums:
        raise RuntimeError(f"public key not found for {username}")

    return nums[-1]


def parse_message(mid, p, q):
    page = get(f"/index.php?page=message&id={mid}")
    soup = BeautifulSoup(page, "html.parser")

    text = soup.get_text("\n")
    nums = [int(x) for x in re.findall(r"\b\d{40,}\b", text)]
    nums = [x for x in nums if x not in (p, q)]

    sig_r = None
    sig_s = None
    canonical_payload = None

    for pre in soup.find_all("pre"):
        content = html.unescape(pre.get_text()).strip()

        sig = re.search(r"(\d{40,})\s*:\s*(\d{40,})", content)
        if sig:
            sig_r = int(sig.group(1))
            sig_s = int(sig.group(2))

        if "message\nfrom=" in content:
            canonical_payload = content

    if sig_r is None or sig_s is None:
        if len(nums) < 2:
            raise RuntimeError(f"signature not found in message {mid}")
        sig_r, sig_s = nums[-2], nums[-1]

    if canonical_payload is None:
        raise RuntimeError(f"canonical payload not found in message {mid}")

    return sig_r, sig_s, canonical_payload


def recover_private_key(q, public_key, r, s1, s2, payload1, payload2):
    e1 = hash_to_scalar(q, public_key, r, payload1)
    e2 = hash_to_scalar(q, public_key, r, payload2)

    if e1 == e2:
        raise RuntimeError("same challenge value, cannot recover key")

    # Schnorr:
    # s1 = k + e1*x mod q
    # s2 = k + e2*x mod q
    # x  = (s1 - s2) / (e1 - e2) mod q
    x = ((s1 - s2) * pow((e1 - e2) % q, -1, q)) % q
    return x


def login_as_admin(p, q, g, x):
    public_key = pow(g, x, p)

    challenge_response = post("challenge", {"username": "admin"}).json()
    challenge = challenge_response["challenge"]

    challenge_id = challenge["id"]
    payload = challenge["payload"]

    # Same as browser JS:
    # k = H("nonce", privateKeyText, payload)
    # r = g^k mod p
    # e = H(y, r, payload)
    # s = k + e*x mod q
    k = hash_to_scalar(q, "nonce", str(x), payload)
    commitment_r = pow(g, k, p)
    e = hash_to_scalar(q, public_key, commitment_r, payload)
    response_s = (k + e * x) % q

    data = {
        "challenge_id": str(challenge_id),
        "username": "admin",
        "nonce": challenge["nonce"],
        "issued_at": str(challenge["issued_at"]),
        "payload": payload,
        "commitment_r": str(commitment_r),
        "response_s": str(response_s),
    }

    result = post("login", data)
    print("[+] login:", result.status_code, result.text[:300])

    if result.status_code != 200 or '"ok":true' not in result.text:
        raise RuntimeError("admin login failed")


def find_flag():
    paths = [
        "/",
        "/index.php",
        "/index.php?page=home",
        "/index.php?page=public",
        "/index.php?page=inbox",
        "/index.php?page=archive",
        "/index.php?page=admin",
        "/index.php?page=profile&user=admin",
    ]

    flag_re = r"uctf\{[^}]+\}|flag\{[^}]+\}|[A-Za-z0-9_]+\{[^}]{8,}\}"

    seen = set()

    for path in paths:
        page = get(path)
        hits = re.findall(flag_re, page)
        if hits:
            print("[+] flag:", hits[0])
            return hits[0]

        for mid in re.findall(r"page=message&id=(\d+)", page):
            seen.add(int(mid))

    for mid in range(1, 150):
        page = get(f"/index.php?page=message&id={mid}")
        hits = re.findall(flag_re, page)
        if hits:
            print(f"[+] flag in message {mid}:", hits[0])
            return hits[0]

    raise RuntimeError("flag not found")


def main():
    p, q, g = parse_config()

    admin_y = get_public_key("admin", p, q)

    r14, s14, payload14 = parse_message(14, p, q)
    r15, s15, payload15 = parse_message(15, p, q)

    print("[+] r14 == r15:", r14 == r15)

    if r14 != r15:
        raise RuntimeError("messages 14 and 15 do not reuse nonce")

    x = recover_private_key(q, admin_y, r14, s14, s15, payload14, payload15)

    print("[+] recovered admin private key:")
    print(x)
    print("[+] key valid:", pow(g, x, p) == admin_y)

    if pow(g, x, p) != admin_y:
        raise RuntimeError("recovered key is invalid")

    login_as_admin(p, q, g, x)
    find_flag()


if __name__ == "__main__":
    main()
