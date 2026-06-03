
def solve():
    with open('pickled.txt', 'r') as f:
        content = f.read().strip().split()
    
    # Map words to bits: rick=0, pickle=1
    bits = ['1' if w == 'pickle' else '0' for w in content]
    
    # Group bits into bytes
    bytes_val = []
    for i in range(0, len(bits), 8):
        byte_str = ''.join(bits[i:i+8])
        bytes_val.append(int(byte_str, 2))
        
    # XOR with 0x67 to get the ELF
    # We found this key by XORing the first byte (0x18) with 0x7f
    decoded = bytes([b ^ 0x67 for b in bytes_val])
    
    with open('recovered_elf', 'wb') as f:
        f.write(decoded)
        
    # The flag is in the data section of the ELF
    # Or we can just run it if we are on Linux
    import subprocess
    import os
    os.chmod('recovered_elf', 0o755)
    result = subprocess.check_output(['./recovered_elf'])
    print(result.decode().strip())

if __name__ == '__main__':
    solve()
