#!/usr/bin/env python3
"""Recover and decrypt the attachment valid at tx=47 from the supplied WAL."""

import hashlib
import pathlib
import sqlite3
import struct
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DB = pathlib.Path("nightjar.db")
WAL = pathlib.Path("nightjar.db-wal")
ANDROID_ID = "a91f32d06c74be18"
THREAD_ID = 17
TARGET_TX = 47
PAGE_SIZE = 4096


def materialize_wal_snapshot(frame_limit: int, output: pathlib.Path) -> None:
    """Apply WAL frames through a commit without touching the evidence files."""
    database = bytearray(DB.read_bytes())
    journal = WAL.read_bytes()
    if journal[:4] != b"7\x7f\x06\x82":
        raise ValueError("unexpected WAL magic")
    page_size = struct.unpack(">I", journal[8:12])[0]
    if page_size != PAGE_SIZE:
        raise ValueError(f"unexpected page size: {page_size}")

    frame_size = 24 + page_size
    frame_count = (len(journal) - 32) // frame_size
    if frame_limit > frame_count:
        raise ValueError("WAL frame limit is out of range")

    max_page = len(database) // page_size
    for index in range(frame_limit):
        offset = 32 + index * frame_size
        page_number = struct.unpack(">I", journal[offset:offset + 4])[0]
        page = journal[offset + 24:offset + frame_size]
        max_page = max(max_page, page_number)
        if len(database) < page_number * page_size:
            database.extend(b"\0" * (page_number * page_size - len(database)))
        start = (page_number - 1) * page_size
        database[start:start + page_size] = page

    # Make the materialized file a normal rollback-journal database.
    struct.pack_into(">I", database, 24, frame_limit)
    struct.pack_into(">I", database, 28, max_page)
    output.write_bytes(database)


def find_snapshot_frame() -> int:
    """Find the WAL commit containing the target tx and its attachment row."""
    journal = WAL.read_bytes()
    frame_size = 24 + PAGE_SIZE
    frames = []
    for index in range((len(journal) - 32) // frame_size):
        offset = 32 + index * frame_size
        commit_size = struct.unpack(">I", journal[offset + 4:offset + 8])[0]
        frames.append((index + 1, commit_size))

    # The supplied WAL has commit boundaries at frames 6, 13, 17 and 24.
    # Search each committed snapshot, so this remains tied to tx=47 rather
    # than relying on a hard-coded attachment payload.
    for index, (_, commit_size) in enumerate(frames, start=1):
        if commit_size == 0:
            continue
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot = pathlib.Path(temp_dir) / "snapshot.db"
            materialize_wal_snapshot(index, snapshot)
            con = sqlite3.connect(snapshot)
            try:
                tx = con.execute(
                    "SELECT 1 FROM txlog WHERE tx=?", (TARGET_TX,)
                ).fetchone()
                ready = con.execute(
                    "SELECT 1 FROM attachments WHERE thread_id=? AND state='ready'",
                    (THREAD_ID,),
                ).fetchone()
            finally:
                con.close()
        if tx and ready:
            return index
    raise RuntimeError("no WAL snapshot contains tx=47 and a ready attachment")


def main() -> None:
    frame = find_snapshot_frame()
    with tempfile.TemporaryDirectory() as temp_dir:
        snapshot = pathlib.Path(temp_dir) / "snapshot.db"
        materialize_wal_snapshot(frame, snapshot)
        con = sqlite3.connect(snapshot)
        tx_ms = con.execute(
            "SELECT committed_ms FROM txlog WHERE tx=?", (TARGET_TX,)
        ).fetchone()[0]
        row = con.execute(
            """SELECT revision, committed_ms, nonce, payload
               FROM attachments
               WHERE thread_id=? AND state='ready' AND committed_ms=?""",
            (THREAD_ID, tx_ms),
        ).fetchone()
        con.close()

    if row is None:
        raise RuntimeError("ready attachment at tx=47 was not recovered")
    revision, committed_ms, nonce, payload = row
    key_material = f"{ANDROID_ID}:{THREAD_ID}:{revision}:{committed_ms}".encode()
    key = hashlib.sha256(key_material).digest()
    aad = f"thread={THREAD_ID};revision={revision}".encode()
    plaintext = AESGCM(key).decrypt(nonce, payload, aad)

    with tempfile.TemporaryDirectory() as temp_dir:
        recovered = pathlib.Path(temp_dir) / "attachment.zip"
        recovered.write_bytes(plaintext)
        with zipfile.ZipFile(recovered) as archive:
            handoff = archive.read("handoff.txt").decode()

    for line in handoff.splitlines():
        if line.startswith("Flag:"):
            flag = line.split(":", 1)[1].strip()
            print(flag)
            return
    raise RuntimeError("flag was not present in handoff.txt")


if __name__ == "__main__":
    main()
