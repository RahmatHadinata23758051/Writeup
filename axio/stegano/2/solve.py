from PIL import Image, ImageChops
import os

print("[*] Memulai proses XOR pada foto-foto Kopatych...")

try:
    # Buka ketiga gambar
    img1 = Image.open("1.png").convert("RGB")
    img2 = Image.open("2.png").convert("RGB")
    img3 = Image.open("3.png").convert("RGB")

    # Cari ukuran terkecil agar bisa di-XOR tanpa error dimensi
    min_width = min(img1.width, img2.width, img3.width)
    min_height = min(img1.height, img2.height, img3.height)

    print(f"[*] Menyamakan dimensi (Crop) ke: {min_width}x{min_height}")

    # Crop gambar ke ukuran yang sama (pojok kiri atas)
    img1_cropped = img1.crop((0, 0, min_width, min_height))
    img2_cropped = img2.crop((0, 0, min_width, min_height))
    img3_cropped = img3.crop((0, 0, min_width, min_height))

    # Operasi XOR: (Img1 XOR Img2) XOR Img3
    print("[*] Mengeksekusi bitwise XOR...")
    xor_1_2 = ImageChops.logical_xor(img1_cropped.convert('1'), img2_cropped.convert('1'))
    final_xor = ImageChops.logical_xor(xor_1_2, img3_cropped.convert('1'))

    # Simpan hasil
    out_file = "flag_result.png"
    final_xor.save(out_file)
    print(f"[+] Selesai! Hasil XOR disimpan sebagai '{out_file}'")

    # Coba juga variasi lain jaga-jaga
    ImageChops.difference(img1_cropped, img2_cropped).save("diff_1_2.png")
    ImageChops.difference(img2_cropped, img3_cropped).save("diff_2_3.png")
    print("[+] File difference (selisih) juga disimpan (diff_1_2.png, diff_2_3.png)")

except Exception as e:
    print(f"[-] Terjadi kesalahan: {e}")
