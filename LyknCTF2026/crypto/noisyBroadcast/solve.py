import binascii

def solve_noisy_broadcast():
    # Kita cukup menggunakan c1. Noise di akhir tidak akan mengubah hasil integer cube root
    c1 = 258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590879169419712047717
    
    print("[*] Mengekstraksi akar pangkat 3 (Integer Cube Root)...")
    
    # Binary search untuk mencari nilai m (akar pangkat 3 dari c1)
    low = 1
    high = c1
    while low <= high:
        mid = (low + high) // 2
        mid3 = mid**3
        if mid3 == c1:
            m = mid
            break
        elif mid3 < c1:
            low = mid + 1
        else:
            high = mid - 1
            
    m = high # Mengambil batas bawah floor(cbrt(c1)) karena noise
    
    # Proses konversi dari Integer ke Teks (Flag)
    hex_m = hex(m)[2:]
    if len(hex_m) % 2 != 0:
        hex_m = '0' + hex_m
        
    try:
        flag = binascii.unhexlify(hex_m).decode('utf-8', errors='ignore')
        print("\n[+] Flag berhasil ditemukan:")
        print(flag)
    except Exception as e:
        print(f"[-] Gagal men-decode flag: {e}")

if __name__ == "__main__":
    solve_noisy_broadcast()
