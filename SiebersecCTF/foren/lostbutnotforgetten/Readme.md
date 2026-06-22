# Lost but Not Forgotten - Writeup

The challenge provides a PDF file `lbng.pdf`. 

## 1. Initial Analysis
Using `grep`, I found that the file contains two `%%EOF` markers and two `startxref` pointers, which indicates that the PDF has been updated incrementally.

```bash
grep -aob "%%EOF" lbng.pdf
# 2376:%%EOF
# 6442:%%EOF
```

This suggests that the "lost" content might be in the first version of the PDF.

## 2. Extracting the First Version
I extracted the first version of the PDF by taking everything up to the first `%%EOF`.

```bash
head -c 2381 lbng.pdf > lbng_v1.pdf
```

## 3. Decompressing the Streams
Upon decompressing the streams in the first version (specifically object 5, which corresponds to the page contents), I found several suspicious strings interleaved with the text:

- `sct`
- `f{m:3t4d4ta_`
- `r3v34l5_`
- `4_`
- `lo7}`

In the second version of the PDF, these strings were replaced with empty strings `()`, confirming they were indeed part of the flag.

## 4. Reconstructing the Flag
Combining the parts in the order they appeared in the document:

`sct` + `f{m:3t4d4ta_` + `r3v34l5_` + `4_` + `lo7}` = `sctf{m:3t4d4ta_r3v34l5_4_lo7}`

The flag follows the "metadata reveals a lot" theme (common in forensics), leet-speakified with some unusual characters.

**Flag:** `sctf{m:3t4d4ta_r3v34l5_4_lo7}`
