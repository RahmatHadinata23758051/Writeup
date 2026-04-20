# CTF Writeup — Final Message

**Event:** JerseyCTF  
**Category:** Crypto / Audio Steganography  
**Difficulty:** Medium  
**Flag:** `jctf{ВОСТОКПРИЗЕМЛИЛСЯ}`

---

## Challenge Description

> Our SIGINT operators picked up a strange AM broadcast a few days ago. Triangulation of the signal indicates it originated from an old Soviet numbers station known to be associated with the Soviet space program and spy satellites. Minutes later, the signal disappeared entirely from our scanners and has not returned. If you listen closely, you can hear a coded message being spoken. Our interns couldn't decrypt it, so it's up to you.
>
> Your objective is to analyze the audio file and retrieve the flag enciphered in the message.
>
> Note: The plaintext message is fully capitalized and uses Cyrillic characters. The flag format stays the same, for example, jctf{}.

**File:** `Final_Message.flac` (48 kHz stereo, ~59.5s)

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file Final_Message.flac
# → FLAC audio

ffprobe -hide_banner Final_Message.flac
# → 48000 Hz, stereo, ~59.5 seconds
```

### Step 2 — Spectrogram Analysis

Generate spectrogram and inspect high-frequency area:

```bash
sox Final_Message.flac -n remix 1 spectrogram -x 3000 -y 1025 -z 120 -w Kaiser -o spec.png
```

Hidden text appears in upper-right region:

`ЛАЙКА`

This is the key hint.

### Step 3 — Decode Spoken Codewords

The spoken message uses Russian radiotelephony words (e.g. `НИКОЛАЙ`, `ОЛЬГА`, `ЦАПЛЯ`, etc.) that map to Cyrillic letters.

Recovered ciphertext:

`НОЫЭОЦПЪУЗРМХУЛЭЯ`

From spectrogram key:

`ЛАЙКА`

---

## Exploitation

### Step 4 — Vigenere Decryption (Cyrillic Alphabet)

Use full Russian alphabet (`АБВГДЕЁ...Я`) and decrypt ciphertext with key `ЛАЙКА`.

```python
ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
KEY = "ЛАЙКА"
CIPHERTEXT = "НОЫЭОЦПЪУЗРМХУЛЭЯ"
```

Decryption result:

`ВОСТОКПРИЗЕМЛИЛСЯ`

### Step 5 — Build Flag

Flag uses original Cyrillic plaintext directly:

`jctf{ВОСТОКПРИЗЕМЛИЛСЯ}`

---

## Flag

```
jctf{ВОСТОКПРИЗЕМЛИЛСЯ}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Spectrogram Steganography** | Key hidden visually in frequency domain (`ЛАЙКА`) |
| 2 | **Classical Cipher (Vigenere)** | Spoken ciphertext decrypted with repeating Cyrillic key |
| 3 | **Radiotelephony Encoding** | Spoken words represent Cyrillic letter stream |

---

## Tools Used

- `sox` / `ffprobe` — audio inspection + spectrogram
- Python — Vigenere decryption automation

---

## Attack Flow

```
Final_Message.flac
      │
      ▼
Spectrogram analysis
      │
      ▼
Hidden key: "ЛАЙКА"
      │
      ▼
Decode spoken radiotelephony words
      │
      ▼
Ciphertext: НОЫЭОЦПЪУЗРМХУЛЭЯ
      │
      ▼
Vigenere decrypt(key="ЛАЙКА")
      │
      ▼
ВОСТОКПРИЗЕМЛИЛСЯ
      │
      ▼
jctf{ВОСТОКПРИЗЕМЛИЛСЯ}
```

---

## Installation

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```
