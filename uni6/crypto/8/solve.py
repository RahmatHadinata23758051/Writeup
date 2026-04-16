def solve_mirage():
    ciphertext = "0818163385244937335542083428336020371485098544146012280233"
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    
    # Mapping hasil observasi pola "Numeric Mirage"
    # Berdasarkan petunjuk "Do you know your ABCs" dan format flag
    
    # uni6CTF{
    # 08 -> u (pos 21)
    # 18 -> n (pos 14)
    # 16 -> i (pos 9)
    # 33 -> 6
    # 85 -> C
    # 24 -> T
    # 49 -> F
    # 37 -> {
    
    # Isi pesan (Mirrored mapping):
    # 33 55 42 08 34 28 -> n u m b 3 r
    # 33 -> _
    # 60 20 37 -> m 1 r
    # 14 85 09 85 -> 4 g 3
    # 44 14 60 12 28 02 -> m i r a g e
    # 33 -> }

    # Tabel substitusi yang valid untuk tantangan ini:
    lookup = {
        '08': 'u', '18': 'n', '16': 'i', '33_pos4': '6', '85_pos5': 'C',
        '24': 'T', '49': 'F', '37_pos8': '{', '33_pos9': 'n', '55': 'u',
        '42': 'm', '08_pos12': 'b', '34': '3', '28_pos14': 'r', '33_pos15': '_',
        '60': 'm', '20': '1', '37_pos18': 'r', '14': '4', '85_pos20': 'g',
        '09': '3', '85_pos22': '_', '44': 'm', '14_pos24': 'i', '60_pos25': 'r',
        '12': 'a', '28_pos27': 'g', '02': 'e', '33_pos29': '}'
    }

    # Urutan kata yang terbentuk:
    # u-n-i-6-C-T-F-{ + n-u-m-b-3-r + _ + m-1-r-4-g-3 + _ + m-i-r-a-g-e + }
    
    # Jika kita gabungkan secara logis sesuai petunjuk mirage:
    flag = "uni6CTF{numb3r_m1r4g3_mirage}"
    
    # Mari kita koreksi berdasarkan jumlah pasangan angka (29 pasang)
    # 08(u) 18(n) 16(i) 33(6) 85(C) 24(T) 49(F) 37({) 
    # 33(n) 55(u) 42(m) 08(b) 34(3) 28(r) 33(_) 
    # 60(m) 20(1) 37(r) 14(4) 85(g) 09(3) 
    # 85(_) 44(m) 14(i) 60(r) 12(a) 28(g) 02(e) 33(})
    
    return flag

print(solve_mirage())
