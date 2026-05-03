import re
import zlib
import base64

def solve():
    with open('crypt.pdf', 'rb') as f:
        content = f.read()
    
    # Find Object 5 which contains the hidden stream
    # It is encoded with ASCII85 and then Flate compressed
    start_marker = b'<~'
    end_marker = b'~>'
    
    start = content.find(start_marker) + 2
    end = content.find(end_marker, start)
    
    if start == 1 or end == -1:
        print("Could not find the hidden stream.")
        return
    
    encoded_data = content[start:end]
    
    # Decode ASCII85
    compressed_data = base64.a85decode(encoded_data)
    
    # Decompress Flate (zlib)
    try:
        decompressed = zlib.decompress(compressed_data).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error decompressing: {e}")
        return
    
    # Extract characters from the stream
    # The flag is formed by characters at y=100
    matches = re.findall(r'BT 1 0 0 1 (\d+) 100 Tm \((.*?)\) Tj ET', decompressed)
    
    # Sort by x coordinate
    matches.sort(key=lambda x: int(x[0]))
    
    flag = "".join([m[1] for m in matches])
    print(f"Found flag: {flag}")

if __name__ == "__main__":
    solve()
