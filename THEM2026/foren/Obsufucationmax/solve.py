import hashlib

def solve():
    with open('chall.png', 'rb') as f:
        data = bytearray(f.read())
    
    key_phrase = b"i have encrypted this cuz my pet said so"
    
    # Decrypt from offset 33 to the end of the encrypted PNG part
    # The clean PNG length is 380633 bytes (ends at the end of IEND chunk)
    for i in range(33, 380633):
        data[i] ^= key_phrase[i % len(key_phrase)]
        
    clean_data = data[:380633]
    
    # Calculate sha256
    sha256_hash = hashlib.sha256(clean_data).hexdigest()
    print(f"Flag: {sha256_hash}")
    
    with open('recovered.png', 'wb') as f:
        f.write(clean_data)

if __name__ == "__main__":
    solve()
