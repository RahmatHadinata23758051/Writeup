import struct
import zlib

def solve():
    input_file = '/home/nata/ctf/THEM2026/misc/veryverygoodchall/media/sf_D_DRIVE/sigma.png'
    output_file = 'fixed.png'

    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    # IHDR starts at offset 12 (after signature and length)
    # Height is at offset 20 (12 + 4 + 4)
    # We found that the decompressed IDAT size (5253661) 
    # divided by row size (1080 * 3 + 1 = 3241) is 1621.
    new_height = 1621
    data[20:24] = struct.pack('>I', new_height)

    # Update IHDR CRC (chunk type 'IHDR' + chunk data)
    # IHDR chunk type starts at offset 12
    # IHDR data is 13 bytes
    ihdr_data = data[12:12+4+13]
    new_crc = zlib.crc32(ihdr_data) & 0xffffffff
    data[12+4+13:12+4+13+4] = struct.pack('>I', new_crc)

    with open(output_file, 'wb') as f:
        f.write(data)
    print(f'Fixed image saved as {output_file}')

if __name__ == '__main__':
    solve()
