def fix_file():
    with open('chall.jpg', 'rb') as f:
        data = f.read()

    # Cari di mana struktur XML/ZIP sebenarnya dimulai
    # Header lokal ZIP selalu dimulai dengan PK\x03\x04 (50 4b 03 04)
    # Di soal, author merusak byte awalnya. 
    # Mari kita cari patokan byte yang masih utuh setelah header yang rusak: \x03\x04\x14\x00\x06\x00\x08\x00
    
    # Berdasarkan xxd kamu:
    # 00000000: 4646 2044 3820 4646 0304 1400 0600 0800
    
    # Kita buang 8 byte pertama (4646 2044 3820 4646) yang merupakan garbage,
    # dan kita ganti dengan signature ZIP yang benar: 50 4B (PK)
    
    fixed_data = b'\x50\x4b' + data[8:]

    with open('presentation.pptx', 'wb') as f:
        f.write(fixed_data)

    print("[+] File berhasil diperbaiki dan disimpan sebagai 'presentation.pptx'")

if __name__ == "__main__":
    fix_file()
