#!/usr/bin/env python3
import re
from itertools import product
from collections import Counter

ciphertext = """ٽवԈ౬ࡆୠߤܚٻaඔ൷ڤच૪ЉٻYɜদVɒச೪މŋɞషԂƸਙϮʛܬࢮแ༪ҋ२eڥڊתҬಊचࡄ૯ʝƏɶদnИப۹ʝԣঔณփப२ƞٽषಕҨƭՇԺʊ৹লđҨOƷߛeʛGđҨOƷߛeʛGđҨOƷߛeʛGđҨOƷߛeݩݘԵಊӻғथੳڋࠅɤకΦʛ੩ຝڛদಷಛւଞਕƜ߆"""

mapping = {
    # Flag format
    "ٽ": "u", "व": "n", "Ԉ": "i", "౬": "6", "ࡆ": "c", "ୠ": "t", "ߤ": "f", "ܚ": "{", "߆": "}",

    # Body
    "a": "h", "ඔ": "a", "൷": "c", "ڤ": "k", "च": "i", "૪": "n", "Љ": "g",
    "ٻ": " ", "Y": "y", "ɜ": "o", "দ": "u",
    "V": "y", "ɒ": "o", "ச": "u", "೪": "r",
    "މ": "k", "ŋ": "n", "ɞ": "o", "ష": "w", "Ԃ": "l", "Ƹ": "e", "ਙ": "d", "Ϯ": "g", "ʛ": "e",
    "ܬ": "g", "ࢮ": "i", "แ": "v", "༪": "e", "ҋ": "s", "२": " ",
    "e": " ", "ڥ": "m", "ڊ": "a", "ת": "k", "Ҭ": "e", "ಊ": "s",
    "ࡄ": " ", "૯": "i", "ʝ": "t",
    "Ə": " ", "ɶ": "f", "И": "e", "ப": "e", "۹": "l",
    "ƞ": "b", "ष": "e", "ಕ": "t", "ƭ": "t", "Շ": "e", "Ժ": "r",
    "ʊ": " ", "৹": "u", "ল": "p",

    # Rickroll-like tail
    "đ": "n", "Ҩ": "e", "O": "v", "Ʒ": "e", "ߛ": "r", "G": "o",
    "ݩ": "n", "ݘ": "n", "Ե": "a", "ӻ": "g", "ғ": "i", "थ": "v", "ੳ": "e",
    "ڋ": "y", "ࠅ": "o", "ɤ": "u", "క": "u", "Φ": "p",
    "੩": "l", "ຝ": "e", "ڛ": "t", "ಷ": "d", "ಛ": "o", "ւ": "w", "ଞ": "n", "ਕ": "!", "Ɯ": "",
}


def decode(text: str, table: dict[str, str]) -> tuple[str, list[tuple[int, str]]]:
    out = []
    unknown = []
    for i, ch in enumerate(text):
        if ch in table:
            out.append(table[ch])
        else:
            out.append(f"[{ch}]")
            unknown.append((i, ch))
    return "".join(out), unknown


def clean_spaces(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace("{ ", "{").replace(" }", "}")
    return text


def extract_flag_candidates(text: str) -> list[str]:
    # strict candidate
    hits = re.findall(r"uni6ctf\{[^}]*\}", text)
    # permissive if still contains unknown marker
    hits += re.findall(r"uni6ctf\{[^\n]*", text)
    # deduplicate preserving order
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def suggest_unknown_mapping(text: str, table: dict[str, str], top_k: int = 10) -> list[tuple[int, dict[str, str], str]]:
    unknown_chars = sorted({ch for ch in text if ch not in table})
    if not unknown_chars:
        return []

    alphabet = " etaoinshrdlucmfwypvbgkjqxz"
    targets = [
        "uni6ctf{", "hacking", "your", "knowledge", "gives", "makes", "it", "feel",
        "better", "up", "never", "gonna", "give", "you", "let", "down", "!}",
    ]

    def decode_with(extra: dict[str, str]) -> str:
        merged = dict(table)
        merged.update(extra)
        raw = "".join(merged.get(ch, "?") for ch in text)
        return clean_spaces(raw)

    def score(decoded: str) -> int:
        s = 0
        for w in targets:
            s += decoded.count(w) * (len(w) * 10)
        s += decoded.count("never") * 20
        s += decoded.count("gonna") * 20
        s += decoded.count("give") * 15
        s += decoded.count("you") * 15
        s += sum(c.isalpha() or c in " {}!6" for c in decoded)
        s -= decoded.count("?") * 50
        return s

    # Beam search to avoid full cartesian explosion.
    beam: list[dict[str, str]] = [{}]
    beam_width = 500
    for ch in unknown_chars:
        candidates: list[tuple[int, dict[str, str]]] = []
        for partial in beam:
            for repl in alphabet:
                nxt = dict(partial)
                nxt[ch] = repl
                dec = decode_with(nxt)
                candidates.append((score(dec), nxt))
        candidates.sort(key=lambda x: x[0], reverse=True)
        beam = [m for _, m in candidates[:beam_width]]

    ranked: list[tuple[int, dict[str, str], str]] = []
    for m in beam:
        dec = decode_with(m)
        ranked.append((score(dec), m, dec))
    ranked.sort(key=lambda x: x[0], reverse=True)
    return ranked[:top_k]


def main() -> None:
    raw, unknown = decode(ciphertext, mapping)
    cleaned = clean_spaces(raw)

    print("=" * 60)
    print("RAW DECODE")
    print("=" * 60)
    print(raw)

    print("\n" + "=" * 60)
    print("CLEANED")
    print("=" * 60)
    print(cleaned)

    print("\n" + "=" * 60)
    print("UNKNOWN CHAR REPORT")
    print("=" * 60)
    if not unknown:
        print("No unknown chars.")
    else:
        cnt = Counter(ch for _, ch in unknown)
        print(f"Unknown total: {len(unknown)}")
        print("Frequency:", dict(cnt))
        print("Context windows:")
        for idx, ch in unknown:
            left = ciphertext[max(0, idx - 6):idx]
            right = ciphertext[idx + 1:idx + 7]
            print(f"  idx={idx:3d} char={ch} context={left}[{ch}]{right}")

    print("\n" + "=" * 60)
    print("FLAG CANDIDATES")
    print("=" * 60)
    cands = extract_flag_candidates(cleaned)
    if not cands:
        print("No complete flag found yet (likely missing mapping for unknown chars).")
    else:
        for c in cands:
            print(c)

    print("\n" + "=" * 60)
    print("UNKNOWN MAPPING SUGGESTIONS")
    print("=" * 60)
    suggestions = suggest_unknown_mapping(ciphertext, mapping, top_k=5)
    if not suggestions:
        print("No unknown characters left.")
    else:
        for i, (sc, m, dec) in enumerate(suggestions, 1):
            print(f"\n[{i}] score={sc} mapping={m}")
            print(dec)


if __name__ == "__main__":
    main()
