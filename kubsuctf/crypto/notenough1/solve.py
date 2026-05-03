from Crypto.Cipher import AES

from hashlib import sha256

from Crypto.Util.number import long_to_bytes, inverse



# --- DATA DARI OUTPUT SAGE ---

p = 12353004157445055980050487940370118697416150159469857511958947381997462856832008638399883311230903934995962952742851634567805109074183537795022583034643467



# --- DATA DARI SOAL ---

N = 151708532784988710186354895816447243710932251919277531742510058529452761722432439526454251312377007965942929512494581288744504881159769296873653469521440122432931073443340101324374399582714454128949856004044525971541673007542812412410730741409339131837689130677766341334202879471841791194383321275827852931391

e = 65537

nonce = bytes.fromhex("8fe6c8d25d0738576b6f6a25")

ciphertext = bytes.fromhex("0094dfe5f358aecb96369cf72731d114bf0a0008cbe1d15b98b30f4fd1492e0ee1567a7fd602dc3ff7aa709ea98e7c06eb261c")

tag = bytes.fromhex("9755d120d8356f29ca31eacff3360ab0")



# 1. Verifikasi p dan cari q

if N % p == 0:

    q = N // p

    print("[+] Faktor p valid!")

else:

    print("[-] Faktor p tidak valid. Periksa kembali input.")

    exit()



# 2. RSA Private Key Calculation

# phi = (p-1)(q-1)

phi = (p - 1) * (q - 1)

d = inverse(e, phi)



# 3. Key Derivation Function (KDF)

# Sesuai deskripsi: sha256(long_to_bytes(secret)).digest()[:16]

# Di mana 'secret' adalah hasil RSA (dalam hal ini d)

secret = d

key = sha256(long_to_bytes(secret)).digest()[:16]



# 4. AES-GCM Decryption

try:

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Dekripsi dan verifikasi tag

    flag = cipher.decrypt_and_verify(ciphertext, tag)

    print(f"\n[!] FLAG DITEMUKAN: {flag.decode()}")

except Exception as err:

    print(f"\n[-] Gagal dekripsi: {err}")

    print("[*] Mencoba secret = p sebagai alternatif...")

    key_alt = sha256(long_to_bytes(p)).digest()[:16]

    try:

        cipher = AES.new(key_alt, AES.MODE_GCM, nonce=nonce)

        flag = cipher.decrypt_and_verify(ciphertext, tag)

        print(f"[!] FLAG DITEMUKAN: {flag.decode()}")

    except:

        print("[-] Semua percobaan secret gagal.")
