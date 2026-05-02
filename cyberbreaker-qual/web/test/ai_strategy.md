# AI Solving Strategy - Northstar

File ini mencatat bagaimana AI (Gemini CLI) menganalisis dan menyelesaikan challenge ini secara otomatis.

## 1. Fase Research
*   **File Discovery**: AI menggunakan `ls -R` dan `read_file` untuk memetakan struktur folder.
*   **Analisis Docker**: Mengetahui flag ada di `/root/flag.txt` dan ada binary `/readflag` yang punya SUID root.
*   **Analisis Proxy**: Menemukan blacklist `proto` di `proxy.py` dan batasan `MAX_PARAMS = 10`.

## 2. Fase Strategi (Hypothesis)
*   **Hipotesis A**: Bypass proxy lewat encoding (UTF-16/32). *Hasil: Gagal (Proxy decoding manual).*
*   **Hipotesis B**: SSRF lewat `X-Forwarded-Host`. *Hasil: Menarik tapi tidak langsung ke flag.*
*   **Hipotesis C**: Multipart header bypass (Parameter duplication). *Hasil: Berhasil.*

## 3. Tooling & Command Penting
*   `curl -sk ...`: Digunakan untuk grab Action ID dari static chunks JS.
*   `requests` (Python): Digunakan untuk crafting custom multipart body karena `curl` susah buat manipulasi dobel parameter di satu header.
*   `Object.prototype` pollution: Target utama untuk mengekstraksi data atau merubah alur program.

## 4. Prompting Flow (Internal Logic)
1.  "Extract all server action IDs from `_next/static/chunks/...`."
2.  "Test if `proxy.py` handles multiple `name` parameters in `Content-Disposition` correctly."
3.  "Pollute `name` property and trigger `processData` with an empty object to leak the polluted value."

## 5. Final Payload Construction
```python
# Core logic used by AI
boundary = "----WebKitFormBoundaryabc123"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="safe"; name="__proto__[name]"\r\n\r\n'
    "TARGET_VALUE\r\n"
    f"--{boundary}--\r\n"
)
```
AI menyadari bahwa dengan memicu error atau response default, nilai yang terpolusi akan terpampang di output.
