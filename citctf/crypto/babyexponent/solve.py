#!/usr/bin/env python3
import binascii

# Data dari soal
n = 3975311104658158367804953186451876987828483822427305148759145730088615027289956528884778329789668637386484932183485546402292017850452360645365142100268336371204659887371551551598753305231985601246101574833959356250563521064956134365407699223
e = 3
c = 21208016443347524194488872231478291493949438339558450377152081476869432669496266457076405093626099218034592769060441274220970709748741037953818131469435699367735940032724483543045224740051080037

def integer_cbrt(target):
    """Mencari akar pangkat tiga dari angka raksasa menggunakan Binary Search"""
    low = 1
    high = target
    while low <= high:
        mid = (low + high) // 2
        mid_cubed = mid ** 3
        
        if mid_cubed == target:
            return mid
        elif mid_cubed < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1 # Jika bukan pangkat tiga sempurna

print("[*] Melakukan serangan Cube Root pada RSA...")
m = integer_cbrt(c)

if m != -1:
    print(f"[*] Plaintext Integer (m) ditemukan: {m}")
    
    # Konversi dari Integer -> Hex -> Bytes -> String ASCII
    hex_string = hex(m)[2:] # Hilangkan awalan '0x'
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string # Pastikan genap
        
    flag = binascii.unhexlify(hex_string).decode('utf-8', errors='ignore')
    
    print("\n" + "="*50)
    print(f"[!] BINGO! FLAG: {flag}")
    print("="*50)
else:
    print("[-] Gagal. Ternyata c bukan pangkat tiga sempurna. Pesan mungkin terlalu panjang (m^3 > n).")
