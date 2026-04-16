from PIL import Image, ImageChops, ImageOps

# 1. Muat semua fragmen (file_13 sampai file_28)
images = []
for i in range(13, 29):
    # Gunakan mode '1' (1-bit pixels, black and white) untuk XOR yang bersih
    img = Image.open(f"output_decrypted/file_{i}.png").convert("1")
    images.append(img)

# 2. Lakukan XOR pada semua gambar
# ImageChops.difference bekerja seperti XOR untuk gambar 1-bit
combined = images[0]
for img in images[1:]:
    combined = ImageChops.difference(combined, img)

# 3. Simpan hasil mentah
combined.save("raw_xor.png")

# 4. Invert hasilnya (QR Code butuh modul hitam di atas putih)
final_qr = ImageOps.invert(combined.convert("L"))
final_qr.save("final_flag_qr.png")

print("XOR gabungan selesai. Cek final_flag_qr.png")
