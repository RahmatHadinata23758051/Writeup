import requests

# Ambil teks referensi dari API yang sama
ref = str(requests.get('https://catfact.ninja/breeds').text)

# Inisialisasi array dengan 50 karakter kosong
answer = ["?"] * 50

# Mapping indeks yang diambil dari homework.py
mapping = {
    1: 3190, 19: 2619, 4: 1754, 0: 2583, 17: 3416, 40: 369, 22: 3142, 
    5: 243, 31: 3038, 24: 3490, 49: 2809, 7: 3293, 11: 999, 14: 2909, 
    26: 2982, 30: 2339, 39: 2339, 3: 1524, 41: 2982, 18: 776, 28: 888, 
    21: 1561, 8: 2505, 32: 747, 15: 3614, 43: 3127, 20: 3619, 44: 642, 
    48: 2706, 46: 3381, 33: 723, 38: 3369, 23: 1107, 34: 692, 25: 537, 
    29: 949, 6: 1208, 10: 2139, 9: 2446, 2: 401, 16: 3025, 12: 1548, 
    13: 984, 36: 1544, 35: 3381, 42: 824, 37: 36, 27: 949, 45: 723, 47: 3381
}

# Isi array answer berdasarkan indeks referensi
for ans_idx, ref_idx in mapping.items():
    answer[ans_idx] = ref[ref_idx]

print("FLAG:", "".join(answer))
