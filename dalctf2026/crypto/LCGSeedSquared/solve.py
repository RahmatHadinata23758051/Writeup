# Output data dari output.txt
outputs = [
    71303168, 8253210177, 28894521096, 34931108342, 323052614304, 21041578670, 
    15704897931, 155496697456, 84031491351, 150466107942, 193873028869, 106715613193, 
    104026392470, 287011114216, 125919570399, 373742585942, 17468880820, 59610055764, 
    154864717592, 277150428610, 171146056200, 178693442688, 394697978439, 157145675498, 
    340027185146, 106659154870, 130642690508, 156379936566, 404855387860, 105916339011, 
    187101094608, 149750274232, 137795584905, 164835132267, 51508099200, 200055589070, 
    19026738060, 17087641857, 414992685823, 97951221108, 93386416761, 243089922018, 
    282636631830, 272413723250
]

def rng(y):
    return pow(int((175 * y + 17) // 14 + 45), 15, 4294967295)

flag = ""

# Berdasarkan huruf pertama 'D' dari "DalCTF{"
x = outputs[0] // ord('D')
flag += 'D'

print(f"[+] Karakter 1: D  |  x: {x}")

# Pecahkan sisa karakter berikutnya
for i in range(1, len(outputs)):
    t = outputs[i]
    x = rng(x)
    
    # Hitung nilai char dari t / x
    if x != 0 and t % x == 0:
        char_code = t // x
        if 32 <= char_code <= 126: # Rentang karakter printable ASCII
            flag += chr(char_code)
        else:
            print(f"[-] Gagal menebak karakter ke-{i+1}, hasil kode ASCII di luar batas.")
            break
    else:
        # Fallback jika terjadi pembagian tidak bulat (presisi float pada integer division chall)
        print(f"[-] Kesalahan sinkronisasi nilai x pada indeks {i}")
        break

print(f"\n[+] Hasil Flag: {flag}")
