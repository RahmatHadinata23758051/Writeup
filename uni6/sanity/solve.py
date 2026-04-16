import re

def solve_ctf(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Regex untuk mencari format UNI6{huruf_angka_underscore}
        pattern = r'UNI6\{[a-zA-Z0-9_]+\}'
        
        # Mencari semua kemungkinan flag
        found_flags = re.findall(pattern, content)
        
        # Menghapus duplikat dan menampilkan hasil
        unique_flags = list(set(found_flags))
        
        print(f"--- Ditemukan {len(unique_flags)} kemungkinan flag ---")
        for i, flag in enumerate(unique_flags, 1):
            print(f"{i}. {flag}")
            
        # Logika analisis: Sanity check biasanya flag yang paling umum/mendasar
        likely_flag = "UNI6{g3n3r4l_rul3s_ch3ck}"
        if likely_flag in unique_flags:
            print(f"\n[!] Rekomendasi Flag: {likely_flag}")
            print("Alasan: Disebutkan di Chapter I sebagai 'satu yang penting' di antara decoy.")
            
    except FileNotFoundError:
        print("File sanity_check.txt tidak ditemukan!")

if __name__ == "__main__":
    # Ganti nama file jika berbeda
    solve_ctf('sanity_check.txt')
