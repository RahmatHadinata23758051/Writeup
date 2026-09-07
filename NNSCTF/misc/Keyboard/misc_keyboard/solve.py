#!/usr/bin/env python3
import bisect
import re
import struct
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOGICDATA = BASE / "keyboard.logicdata"

# Offsets found from the Saleae Logic 1.x .logicdata container.
# The two channel tables hold coarse transition rows; the raw streams before them
# hold 7-bit delta encoded intermediate transitions.
A_TABLE = (0x12A3D4, 0xD96A14)
B_TABLE = (0xE5A5A0, 0x117AC60)
A_RAW = 0x1B1
B_RAW = 0xD96A3E
PAIR_TOL = 7
CANDIDATE_GAP = 80
TOL_FRAC = 0.46

PID_NAMES = {
    0x1: "OUT",
    0x9: "IN",
    0x5: "SOF",
    0xD: "SETUP",
    0x3: "DATA0",
    0xB: "DATA1",
    0x2: "ACK",
    0xA: "NAK",
    0xE: "STALL",
}


def expand_channel(buf: bytes, table_start: int, table_end: int, raw_start: int) -> list[int]:
    rows = [struct.unpack_from("<QQQQ", buf, off) for off in range(table_start, table_end, 32)]
    if not rows:
        raise ValueError("empty transition table")

    max_idx = max(row[1] for row in rows) + 1
    raw = buf[raw_start : raw_start + max_idx]
    deltas = [byte & 0x7F for byte in raw]

    prefix = [0]
    for delta in deltas:
        prefix.append(prefix[-1] + delta)

    times = [rows[0][0]]
    for cur, nxt in zip(rows, rows[1:]):
        i, j = cur[1], nxt[1]
        dt = nxt[0] - cur[0]
        if j > i and j <= len(deltas) and prefix[j] - prefix[i] == dt:
            t = cur[0]
            for k in range(i, j):
                t += deltas[k]
                if t != times[-1]:
                    times.append(t)
        elif nxt[0] != times[-1]:
            times.append(nxt[0])

    return sorted(set(times))


def pair_differential_edges(a_times: list[int], b_times: list[int]) -> list[float]:
    i = j = 0
    edges: list[float] = []
    while i < len(a_times) and j < len(b_times):
        diff = a_times[i] - b_times[j]
        if abs(diff) <= PAIR_TOL:
            edges.append((a_times[i] + b_times[j]) / 2.0)
            i += 1
            j += 1
        elif a_times[i] < b_times[j]:
            i += 1
        else:
            j += 1
    return edges


def candidate_edge_indexes(b_times: list[int], edges: list[float]) -> list[int]:
    out: list[int] = []
    for i, t in enumerate(b_times):
        if i != 0 and t - b_times[i - 1] <= CANDIDATE_GAP:
            continue
        pos = bisect.bisect_left(edges, t - 8)
        best = None
        for q in range(pos - 2, pos + 3):
            if 0 <= q < len(edges) and (best is None or abs(edges[q] - t) < abs(edges[best] - t)):
                best = q
        if best is not None and abs(edges[best] - t) <= 8 and (not out or out[-1] != best):
            out.append(best)
    return out


def bits_to_bytes(bits: list[int]) -> list[int]:
    result = []
    for pos in range(0, len(bits) // 8 * 8, 8):
        value = 0
        for bit_index, bit in enumerate(bits[pos : pos + 8]):
            value |= bit << bit_index
        result.append(value)
    return result


def unstuff(bits: list[int]) -> list[int]:
    out = []
    ones = 0
    for bit in bits:
        if ones == 6 and bit == 0:
            ones = 0
            continue
        out.append(bit)
        ones = ones + 1 if bit else 0
    return out


def valid_pid(pid: int) -> bool:
    return ((pid & 0x0F) ^ (pid >> 4)) == 0x0F


def fit_sync(edges: list[float], edge_index: int) -> tuple[float, float] | None:
    if edge_index + 6 >= len(edges):
        return None
    ys = edges[edge_index : edge_index + 7]
    if any(not (10 <= ys[i + 1] - ys[i] <= 24) for i in range(6)):
        return None

    # Linear fit for the seven zero bits in the USB sync pattern.
    mean_x = 3.0
    mean_y = sum(ys) / 7.0
    den = sum((x - mean_x) ** 2 for x in range(7))
    bit_time = sum((x - mean_x) * (y - mean_y) for x, y in zip(range(7), ys)) / den
    t0 = mean_y - bit_time * mean_x
    if 14 <= bit_time <= 19.5:
        return t0, bit_time
    return None


def decode_packet(edges: list[float], edge_index: int, max_bits: int = 128) -> tuple[float, list[int]] | None:
    sync_fit = fit_sync(edges, edge_index)
    if sync_fit is None:
        return None
    t0, bit_time = sync_fit
    tolerance = bit_time * TOL_FRAC
    bits: list[int] = []
    edge_ptr = edge_index

    for n in range(max_bits):
        target = t0 + n * bit_time
        while edge_ptr < len(edges) and edges[edge_ptr] < target - tolerance:
            edge_ptr += 1
        if edge_ptr < len(edges) and abs(edges[edge_ptr] - target) <= tolerance:
            bits.append(0)
            edge_ptr += 1
        else:
            bits.append(1)

    return t0, bits_to_bytes(unstuff(bits))


def extract_hid_reports(a_times: list[int], b_times: list[int], edges: list[float]) -> list[tuple[float, bytes]]:
    reports = []
    for edge_index in candidate_edge_indexes(b_times, edges):
        decoded = decode_packet(edges, edge_index)
        if decoded is None:
            continue
        t0, packet = decoded
        if len(packet) < 12 or packet[0] != 0x80 or not valid_pid(packet[1]):
            continue
        if PID_NAMES.get(packet[1] & 0x0F) in {"DATA0", "DATA1"}:
            reports.append((t0, bytes(packet[2:10])))
    return reports


# Approximation of a Norwegian keyboard layout. The clue text contains Norwegian
# words and braces are typed as AltGr+7 / AltGr+0, not US Shift+[ / Shift+].
NORMAL = {code: char for code, char in enumerate("abcdefghijklmnopqrstuvwxyz", 0x04)}
SHIFT = {code: char.upper() for code, char in enumerate("abcdefghijklmnopqrstuvwxyz", 0x04)}
ALTGR = {}

for code, char in enumerate("1234567890", 0x1E):
    NORMAL[code] = char
for code, char in zip(range(0x1E, 0x28), '!"#¤%&/()='):
    SHIFT[code] = char
for code, char in [(0x1F, "@"), (0x20, "£"), (0x21, "$"), (0x22, "€"), (0x24, "{"), (0x25, "["), (0x26, "]"), (0x27, "}")]:
    ALTGR[code] = char

NORMAL.update({
    0x28: "\n", 0x2B: "\t", 0x2C: " ", 0x2D: "+", 0x2E: "´",
    0x2F: "å", 0x30: "¨", 0x31: "'", 0x32: "<", 0x33: "ø",
    0x34: "æ", 0x35: "|", 0x36: ",", 0x37: ".", 0x38: "-",
})
SHIFT.update({
    0x28: "\n", 0x2B: "\t", 0x2C: " ", 0x2D: "?", 0x2E: "`",
    0x2F: "Å", 0x30: "^", 0x31: "*", 0x32: ">", 0x33: "Ø",
    0x34: "Æ", 0x35: "§", 0x36: ";", 0x37: ":", 0x38: "_",
})
ALTGR.update({0x2D: "\\", 0x30: "~", 0x35: "|"})


def key_to_char(keycode: int, modifier: int) -> str | None:
    if modifier & 0x40 and keycode in ALTGR:
        return ALTGR[keycode]
    if modifier & 0x22:
        return SHIFT.get(keycode)
    return NORMAL.get(keycode)


def replay_keyboard(reports: list[tuple[float, bytes]]) -> str:
    buf: list[str] = []
    cursor = 0
    previous_keys: set[int] = set()

    for _, report in reports:
        modifier = report[0]
        keys = [key for key in report[2:8] if key]
        current_keys = set(keys)

        for keycode in [key for key in keys if key not in previous_keys]:
            if keycode == 0x2A:  # Backspace
                if cursor > 0:
                    del buf[cursor - 1]
                    cursor -= 1
            elif keycode == 0x4C:  # Delete
                if cursor < len(buf):
                    del buf[cursor]
            elif keycode == 0x4F:  # Right arrow
                cursor = min(len(buf), cursor + 1)
            elif keycode == 0x50:  # Left arrow
                cursor = max(0, cursor - 1)
            elif keycode == 0x4A:  # Home: start of current line
                left = "".join(buf[:cursor]).rfind("\n")
                cursor = 0 if left == -1 else left + 1
            elif keycode == 0x4D:  # End: end of current line
                text = "".join(buf)
                right = text.find("\n", cursor)
                cursor = len(buf) if right == -1 else right
            elif keycode in {0x49, 0x4B, 0x4E, 0x51, 0x52}:
                # Insert/PageUp/PageDown/Up/Down are not needed for the flag line.
                pass
            else:
                char = key_to_char(keycode, modifier)
                if char is not None:
                    buf.insert(cursor, char)
                    cursor += 1

        previous_keys = current_keys

    return "".join(buf)


def main() -> None:
    if not LOGICDATA.exists():
        raise SystemExit(f"missing {LOGICDATA.name}")
    buf = LOGICDATA.read_bytes()

    a_times = expand_channel(buf, *A_TABLE, A_RAW)
    b_times = expand_channel(buf, *B_TABLE, B_RAW)
    edges = pair_differential_edges(a_times, b_times)
    reports = extract_hid_reports(a_times, b_times, edges)
    decoded = replay_keyboard(reports)

    print(f"transitions: A={len(a_times)} B={len(b_times)}")
    print(f"differential edges: {len(edges)}")
    print(f"hid reports: {len(reports)}")

    flags = re.findall(r"NNS\{[^}\n]*\}", decoded)
    if not flags:
        print(decoded)
        raise SystemExit("flag pattern not found")

    flag = flags[0]
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
