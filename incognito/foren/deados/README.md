# Dead OS - Full Forensic Write-up

## Challenge
- Category: Forensics
- Name: `Dead OS`
- Flag format: `IIITL{...}`

## Investigation Strategy
The challenge description says the OS does not boot, but data is intact.  
That strongly suggests hidden data in boot-related structures (MBR/bootloader) plus a key chain somewhere in user artifacts.

The successful chain was:
1. Find suspicious user artifacts.
2. Recover encrypted key material.
3. Crack/decrypt the key material.
4. Use recovered key against hidden payload in the boot sector.

---

## 1) Initial Recon

### Command
```bash
ls -la
```

### Output
```text
total 20971536
drwxr-xr-x 2 nata nata        4096 Apr 14 09:43 .
drwxr-xr-x 5 nata nata        4096 Apr 14 09:43 ..
-rw-r--r-- 1 nata nata 21474836992 Apr 14 01:08 Dead_OS.vhd
```

Only one artifact exists: a very large VHD.

### Command
```bash
file Dead_OS.vhd
```

### Output
```text
Dead_OS.vhd: DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "iumuhAh5x1NWNh6Twkk9xDn0ZwlKn3yJ7C4FVZ1z/PY=ing system" at offset 0x17b "ZwlKn3yJ7C4FVZ1z/PY=ing system" at offset 0x19a "Missing operating system", disk signature 0xed2553d4
```

Important clue appears immediately: boot message area includes suspicious Base64-like text.

### Command
```bash
mmls Dead_OS.vhd
```

### Output
```text
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000104447   0000102400   NTFS / exFAT (0x07)
003:  000:001   0000104448   0040868324   0040763877   NTFS / exFAT (0x07)
004:  -------   0040868325   0040869887   0000001563   Unallocated
005:  000:002   0040869888   0041938943   0001069056   Unknown Type (0x27)
006:  -------   0041938944   0041943039   0000004096   Unallocated
```

Main user data is in NTFS partition at offset `104448`.

---

## 2) Triage on Main NTFS Partition

### Command
```bash
fls -o 104448 -pr Dead_OS.vhd | rg -i "hidden|vault|key|flag|secret|lock|message" | head -n 30
```

### Output (relevant lines)
```text
r/r 109998-128-1:  Users/You/AppData/Roaming/HiddenApp/key.zip
r/r 110020-128-4:  Users/You/AppData/Roaming/Microsoft/Windows/Recent/HiddenApp.lnk
r/r 108874-128-1:  Users/You/AppData/Roaming/Microsoft/Windows/Recent/key.lnk
```

This is the strongest lead: `HiddenApp/key.zip`.

---

## 3) Extract and Inspect key.zip

### Command
```bash
icat -o 104448 Dead_OS.vhd 109998-128-1 > key.zip
7z l -slt key.zip
```

### Output
```text
Path = key.zip
Type = zip
Physical Size = 192

Path = key.txt
Size = 32
Packed Size = 44
Encrypted = +
Method = ZipCrypto Store
```

So `key.txt` exists but ZIP is encrypted.

---

## 4) Crack key.zip Password

### Command
```bash
zip2john key.zip > keyzip.hash
cat keyzip.hash
```

### Output
```text
key.zip/key.txt:$pkzip$1*1*2*0*2c*20*ed847557*0*25*0*2c*ed84*598f0c974148d25b81769330b44d6bfb92f07f68b896bf4c0b47a493ab0b674cd8448e35354944887d229481*$/pkzip$:key.txt:key.zip::key.zip
```

### Command
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt key.zip
```

### Output
```text
PASSWORD FOUND!!!!: pw == Passw0rd123
```

Recovered ZIP password: `Passw0rd123`.

---

## 5) Recover Key from key.txt

### Command
```bash
unzip -P 'Passw0rd123' -o key.zip -d key_zip_out
cat key_zip_out/key.txt
```

### Output
```text
ThisIsA32ByteKeyForAES256!!12345
```

That value is exactly 32 bytes, suitable for AES-256 key.

---

## 6) Validate Suspicious Data in MBR

### Command
```bash
xxd -g 1 -s 0x150 -l 160 Dead_OS.vhd
```

### Output
```text
00000160: 24 02 c3 69 75 6d 75 68 41 68 35 78 31 4e 57 4e
00000170: 68 36 54 77 6b 6b 39 78 44 6e 30 5a 77 6c 4b 6e
00000180: 33 79 4a 37 43 34 46 56 5a 31 7a 2f 50 59 3d 69
00000190: 6e 67 20 73 79 73 74 65 6d 00 4d 69 73 73 69 6e
```

ASCII part in that range:
```text
iumuhAh5x1NWNh6Twkk9xDn0ZwlKn3yJ7C4FVZ1z/PY=
```

This is a 44-char Base64 blob, which decodes to 32 bytes.

---

## 7) Final Decryption (AES-256-ECB)

### Command
```bash
echo -n 'iumuhAh5x1NWNh6Twkk9xDn0ZwlKn3yJ7C4FVZ1z/PY=' | base64 -d > mbr_blob.bin
KEYHEX=$(echo -n 'ThisIsA32ByteKeyForAES256!!12345' | xxd -p -c 256)
openssl enc -d -aes-256-ecb -K "$KEYHEX" -nopad -in mbr_blob.bin | xxd
openssl enc -d -aes-256-ecb -K "$KEYHEX" -nopad -in mbr_blob.bin
```

### Output
```text
00000000: 4949 4954 4c7b 3533 7231 3075 356c 7921  IIITL{53r10u5ly!
00000010: 215f 555f 5233 7631 7633 645f 3174 7d01  !_U_R3v1v3d_1t}.
```

Plaintext (trim control byte `0x01` at end):
```text
IIITL{53r10u5ly!!_U_R3v1v3d_1t}
```

---

## Final Flag

```text
IIITL{53r10u5ly!!_U_R3v1v3d_1t}
```

---

## Reproduction with solve.py

### Command
```bash
python3 solve.py
```

### Output
```text
IIITL{53r10u5ly!!_U_R3v1v3d_1t}
```

Optional mode (read key from ZIP directly):

### Command
```bash
python3 solve.py --key-zip key.zip --zip-password Passw0rd123
```

### Output
```text
IIITL{53r10u5ly!!_U_R3v1v3d_1t}
```
