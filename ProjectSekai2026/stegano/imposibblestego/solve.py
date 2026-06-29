#!/usr/bin/env python3
"""Recover the hidden message from impossible-stego using the leaked Claude log."""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


FLAG_RE = re.compile(rb"SEKAI\{[^\r\n}]+\}")
PROJECT_PREFIX = "/home/claude/projects/impossible-stego/"


class SolveError(RuntimeError):
    pass


def safe_extract_tar(archive: Path, output_dir: Path) -> None:
    """Extract a tar archive while rejecting path traversal entries."""
    output_dir = output_dir.resolve()
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            target = (output_dir / member.name).resolve()
            try:
                target.relative_to(output_dir)
            except ValueError as exc:
                raise SolveError(f"unsafe archive member: {member.name}") from exc
        try:
            tf.extractall(output_dir, filter="data")
        except TypeError:
            # Compatibility with Python versions predating tarfile filters.
            tf.extractall(output_dir)


def locate_inputs(root: Path) -> tuple[Path, Path]:
    logs = sorted(root.rglob("messages.log"))
    images = sorted(root.rglob("flag.png"))
    if not logs:
        raise SolveError("messages.log not found")
    if not images:
        raise SolveError("flag.png not found")
    return logs[0], images[0]


def decode_json_body(value: str) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        obj = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def recover_conversation(log_path: Path) -> list[dict[str, Any]]:
    """Pick the most complete Claude request; later requests contain prior turns."""
    best: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SolveError(f"invalid JSON on log line {line_number}") from exc

            request = decode_json_body(record.get("req_body", ""))
            messages = request.get("messages") if request else None
            if isinstance(messages, list) and len(messages) > len(best):
                best = messages

    if not best:
        raise SolveError("no Claude conversation found in req_body fields")
    return best


def iter_tool_calls(messages: list[dict[str, Any]]):
    for message in messages:
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                yield block.get("name"), block.get("input", {})


def reconstruct_stego_package(messages: list[dict[str, Any]], destination: Path) -> None:
    """Replay Claude's Write/Edit calls for files inside the final stego package."""
    writes = 0
    edits = 0

    for tool_name, tool_input in iter_tool_calls(messages):
        if not isinstance(tool_input, dict):
            continue
        source_path = tool_input.get("file_path")
        if not isinstance(source_path, str) or not source_path.startswith(PROJECT_PREFIX):
            continue

        relative = source_path[len(PROJECT_PREFIX):]
        # Ignore the discarded single-file prototype and documentation.
        if not relative.startswith("stego/"):
            continue

        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)

        if tool_name == "Write":
            content = tool_input.get("content")
            if not isinstance(content, str):
                raise SolveError(f"Write call for {relative} has no text content")
            target.write_text(content, encoding="utf-8")
            writes += 1

        elif tool_name == "Edit":
            if not target.exists():
                raise SolveError(f"Edit references missing file: {relative}")
            old = tool_input.get("old_string")
            new = tool_input.get("new_string")
            if not isinstance(old, str) or not isinstance(new, str):
                raise SolveError(f"invalid Edit call for {relative}")

            text = target.read_text(encoding="utf-8")
            if tool_input.get("replace_all"):
                if old not in text:
                    raise SolveError(f"Edit pattern not found in {relative}")
                text = text.replace(old, new)
            else:
                count = text.count(old)
                if count != 1:
                    raise SolveError(
                        f"Edit pattern count for {relative} is {count}, expected 1"
                    )
                text = text.replace(old, new, 1)
            target.write_text(text, encoding="utf-8")
            edits += 1

    required = destination / "stego" / "pipeline.py"
    if not required.exists():
        raise SolveError("failed to reconstruct the final stego package")
    if writes < 10 or edits < 1:
        raise SolveError("conversation did not contain the expected source history")


def extract_payload(source_root: Path, image_path: Path) -> bytes:
    sys.path.insert(0, str(source_root))
    try:
        # Avoid reusing a module from an earlier run in the same interpreter.
        for name in list(sys.modules):
            if name == "stego" or name.startswith("stego."):
                del sys.modules[name]
        stego = importlib.import_module("stego")
        return stego.extract(str(image_path))
    except ModuleNotFoundError as exc:
        if exc.name == "PIL":
            raise SolveError("Pillow is required: python3 -m pip install pillow") from exc
        raise
    finally:
        sys.path.pop(0)


def solve(input_path: Path) -> bytes:
    input_path = input_path.resolve()
    if not input_path.exists():
        raise SolveError(f"input does not exist: {input_path}")

    work_parent = input_path.parent if input_path.is_file() else input_path
    with tempfile.TemporaryDirectory(prefix=".solve-impossible-stego-", dir=work_parent) as tmp:
        workspace = Path(tmp)
        if input_path.is_file():
            safe_extract_tar(input_path, workspace)
            search_root = workspace
        else:
            search_root = input_path

        log_path, image_path = locate_inputs(search_root)
        messages = recover_conversation(log_path)
        source_root = workspace / "recovered_source"
        reconstruct_stego_package(messages, source_root)
        payload = extract_payload(source_root, image_path)

    match = FLAG_RE.search(payload)
    if not match:
        raise SolveError(f"payload recovered, but no SEKAI flag found: {payload!r}")
    return match.group(0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solve SEKAI CTF 2026 misc/impossible stego"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="misc_impossible-stego.tar.gz",
        help="challenge archive or an extracted directory",
    )
    args = parser.parse_args()

    try:
        flag = solve(Path(args.input))
    except (OSError, SolveError, tarfile.TarError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"<FLAG>{flag.decode()}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
