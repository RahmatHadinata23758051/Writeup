import sys
import string

print("""
================================================
  Barash Poem Stegano Solver (The True Rhyme)
================================================
""")

# Fungsi untuk mengambil akhiran rima (vokal terakhir + sisanya)
def get_rhyme_part(word):
    vowels = "аеёиоуыэюя" # Huruf vokal Rusia
    for i in range(len(word)-1, -1, -1):
        if word[i] in vowels:
            return word[i:]
    return word

try:
    with open('barash_poem.txt', 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit()

binary_result = ""

for i in range(0, len(lines) - 1, 2):
    w1 = lines[i].split()[-1].lower().rstrip(string.punctuation)
    w2 = lines[i+1].split()[-1].lower().rstrip(string.punctuation)
    
    # Ekstrak rima sejatinya
    r1 = get_rhyme_part(w1)
    r2 = get_rhyme_part(w2)
    
    if r1 == r2:
        binary_result += '1'
    else:
        binary_result += '0'

# Konversi ke ASCII
chars = []
for i in range(0, len(binary_result), 8):
    byte = binary_result[i:i+8]
    if len(byte) == 8:
        chars.append(chr(int(byte, 2)))

flag = "".join(chars)

print(f"[*] Total Baris : {len(lines)}")
print(f"[*] Total Bit   : {len(binary_result)} bits ({len(binary_result)//8} bytes)")
print(f"[*] Binary Dump : {binary_result[:40]}...\n")

print("="*60)
print(" 🏴‍☠️ FLAG DITEMUKAN:")
print("="*60)
print(flag)
print("="*60 + "\n")
