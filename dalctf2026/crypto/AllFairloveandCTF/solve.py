ciphertext = "CLDYIKMHILSUKCLQBF"

# Representasi matriks 5x5
matrix = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z']
]

def find_pos(char):
    if char == 'J':
        char = 'I'
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

plaintext = ""
# Pecah ciphertext jadi pasangan huruf
pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]

for p1, p2 in pairs:
    r1, c1 = find_pos(p1)
    r2, c2 = find_pos(p2)
    
    if r1 == r2: # Baris sama, geser kiri
        plaintext += matrix[r1][(c1 - 1) % 5]
        plaintext += matrix[r2][(c2 - 1) % 5]
    elif c1 == c2: # Kolom sama, geser atas
        plaintext += matrix[(r1 - 1) % 5][c1]
        plaintext += matrix[(r2 - 1) % 5][c2]
    else: # Membentuk kotak, ambil sudut berlawanan di baris yang sama
        plaintext += matrix[r1][c2]
        plaintext += matrix[r2][c1]

print(f"[+] Plaintext Mentah: {plaintext}")
print(f"[+] Flag Format: dalctf{{{plaintext.lower()}}}")
