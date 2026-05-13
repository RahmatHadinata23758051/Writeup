# CTF Writeup — PixelPerfect

**Event:** RAM  
**Category:** Forensics  
**Difficulty:** Easy  
**Flag:** `RAM{m3t4d4t4_n0t_c13an3d}`

---

## Challenge Description

> We are given a single file, `chall.jpg`, and need to recover the hidden flag from it.

**Attachment:** `chall.jpg`

---

## Reconnaissance

### Step 1 — Identify the File

The provided artifact is a JPEG image:

```bash
file chall.jpg
```

Output:

```text
chall.jpg: JPEG image data, JFIF standard 1.01, 400x400
```

At first glance the image looks normal, so the next step is to inspect metadata and check whether extra data is appended to the file.

### Step 2 — Inspect EXIF Metadata

Running `exiftool` reveals a suspicious value in the `Artist` tag:

```bash
exiftool chall.jpg
```

Relevant output:

```text
Artist : Password: super_secret_recovery_key_2026
```

This is a strong indicator that the JPEG metadata was intentionally left dirty and contains the password for another hidden artifact.

### Step 3 — Detect Embedded Data

Next, check whether the JPEG contains appended files:

```bash
binwalk chall.jpg
```

Output:

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
3206          0xC86           Zip archive data, encrypted at least v2.0 to extract, compressed size: 85, uncompressed size: 55, name: flag.txt
3405          0xD4D           End of Zip archive, footer length: 22
```

This confirms that an encrypted ZIP archive is appended after the JPEG data.

---

## Exploitation

### Step 4 — Extract the Embedded ZIP

The simplest way is to let `binwalk` extract the appended archive automatically:

```bash
binwalk -e chall.jpg
```

This produces:

```text
_chall.jpg.extracted/C86.zip
```

### Step 5 — Use the EXIF Password

Now extract the ZIP using the password found in the `Artist` EXIF field:

```bash
7z x -psuper_secret_recovery_key_2026 _chall.jpg.extracted/C86.zip
```

The archive contains a single file:

```text
flag.txt
```

### Step 6 — Read the Flag

```bash
cat flag.txt
```

Output:

```text
Well done! Here is your flag: RAM{m3t4d4t4_n0t_c13an3d}
```

The flag is:

```text
RAM{m3t4d4t4_n0t_c13an3d}
```

---

## Forensic Findings Summary

| # | Finding | Detail |
|---|---|---|
| 1 | **Sensitive EXIF Metadata** | The JPEG `Artist` tag stores the ZIP password in plaintext |
| 2 | **Appended Archive** | An AES-encrypted ZIP archive is concatenated to the end of the JPEG |
| 3 | **Incomplete Cleanup** | The challenge relies on leftover metadata and hidden embedded content |

---

## Remediation

1. **Sanitize metadata before publishing files** — strip EXIF fields from images unless they are explicitly needed
2. **Check for appended payloads** — validate distributed media to ensure no extra archives or data blobs are attached
3. **Automate content inspection** — include metadata scanning and file integrity checks in release workflows

---

## Tools Used

- `file` — identify the main artifact type
- `exiftool` — inspect EXIF metadata
- `binwalk` — detect and extract appended ZIP data
- `7z` — decrypt and extract the AES-protected archive

---

## Attack Flow

```text
Open chall.jpg
      |
      v
Inspect EXIF metadata
  Artist = "Password: super_secret_recovery_key_2026"
      |
      v
Run binwalk on chall.jpg
  -> find embedded encrypted ZIP at 0xC86
      |
      v
Extract ZIP from the JPEG
      |
      v
Use EXIF password to decrypt archive
      |
      v
Read flag.txt
      |
      v
RAM{m3t4d4t4_n0t_c13an3d}
```
