import re
with open('chall.pcap', 'rb') as f:
    content = f.read()
# Mencari pola 7e 01 22 10 1e 00 [DATA] 7e
pattern = b'\x7e\x01\x22\x10\x1e\x00(.*?)\x7e'
matches = re.findall(pattern, content, re.DOTALL)
zip_data = b""
for m in matches:
    # Proses unescape SLIP protocol
    zip_data += m.replace(b'\x7d\x5e', b'\x7e').replace(b'\x7d\x5d', b'\x7d')
with open('final_flag.zip', 'wb') as f:
    f.write(zip_data)
print(f"Berhasil mengekstrak {len(matches)} chunk ke final_flag.zip")
