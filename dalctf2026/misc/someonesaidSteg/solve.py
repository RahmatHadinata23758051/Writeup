import struct
import zlib

def solve():
    flag = ""
    with open('chall.png', 'rb') as f:
        f.read(8) # PNG Magic
        while True:
            chunk_header = f.read(8)
            if not chunk_header: break
            length, name = struct.unpack('>I4s', chunk_header)
            data = f.read(length)
            f.read(4) # CRC
            if name == b'IDAT':
                d = zlib.decompress(data)
                flag += chr(d[4]) # Alpha channel of pixel (0,0)
            elif name == b'fdAT':
                d = zlib.decompress(data[4:])
                flag += chr(d[4]) # Alpha channel of pixel (0,0)
    print(flag)

if __name__ == "__main__":
    solve()
