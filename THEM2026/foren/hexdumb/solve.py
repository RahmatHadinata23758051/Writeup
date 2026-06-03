import zlib

# Hex transcribed from the screenshot
hex_dump = '''
50 4b 03 04 0a 00 09 00 00 00 01 75 98 5c 0f de
90 6f 20 00 00 00 14 00 00 00 08 00 1c 00 66 6c
61 67 2e 74 78 74 55 54 09 00 03 02 b9 eb 69 02
b9 eb 69 75 78 0b 00 01 04 e8 03 00 00 04 e8 03
00 00 5d 81 87 1d 8c 4b 2f 2a 4d af f2 f0 3a 1b
95 84 f3 b7 a8 c9 be 77 cf 1d 92 4a de 9d eb e9
95 c3 50 4b 07 08 0f de 90 6f 20 00 00 00 14 00
00 00 50 4b 01 02 1e 03 0a 00 09 00 00 00 01 75
98 5c 0f de 90 6f 20 00 00 00 14 00 00 00 08 00
18 00 00 00 00 00 01 00 00 00 b4 81 00 00 00 00
66 6c 61 67 2e 74 78 74 55 54 05 00 03 02 b9 eb
69 75 78 0b 00 01 04 e8 03 00 00 04 e8 03 00 00
50 4b 05 06 00 00 00 00 01 00 01 00 4e 00 00 00
72 00 00 00 00 00
'''

zip_bytes = bytes.fromhex(hex_dump)
open('recovered.zip', 'wb').write(zip_bytes)

flag = b'THEM?!CTF{b36vhdum5}'
assert len(flag) == 20
assert zlib.crc32(flag) & 0xffffffff == 0x6f90de0f
print(flag.decode())
print('[+] recovered.zip written')
print('[+] CRC32 verified: 0x%08x' % (zlib.crc32(flag) & 0xffffffff))

