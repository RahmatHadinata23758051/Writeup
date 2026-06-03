import subprocess
import re
import sys

def solve():
    print("[*] Extracting text from confidential.pdf...")
    try:
        # pdftotext akan mengekstrak semua teks mentah, 
        # mengabaikan teks yang warnanya disamakan dengan background atau yang ditutupi kotak hitam
        result = subprocess.run(['pdftotext', 'confidential.pdf', '-'], capture_output=True, text=True, check=True)
        text = result.stdout
        
        # Mencari string dengan pola flag
        flags = re.findall(r'THEM\?!CTF\{.*?\}', text)
        
        # Menghapus duplikat namun tetap menjaga urutannya
        unique_flags = list(dict.fromkeys(flags))
        
        if unique_flags:
            print("[+] Flags berhasil ditemukan!")
            for idx, flag in enumerate(unique_flags):
                print(f"    Confidential Part {idx+1}: {flag}")
        else:
            print("[-] Tidak ada flag yang ditemukan.")
            
    except FileNotFoundError:
        print("[-] Tool 'pdftotext' tidak ditemukan di sistem. Pastikan poppler-utils sudah terinstall.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")
        sys.exit(1)

if __name__ == '__main__':
    solve()
