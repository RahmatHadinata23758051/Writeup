def bits_to_bytes(bit_str):
    byte_arr = bytearray()
    for i in range(0, len(bit_str), 8):
        byte = bit_str[i:i+8]
        if len(byte) == 8:
            byte_arr.append(int(byte, 2))
    return byte_arr

def bits_to_bytes_rev(bit_str):
    byte_arr = bytearray()
    for i in range(0, len(bit_str), 8):
        byte = bit_str[i:i+8]
        if len(byte) == 8:
            byte_arr.append(int(byte[::-1], 2))
    return byte_arr

def decode_deltas(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    vals = [float(line.strip()) for line in lines]
    
    # Try including the first 0.0 or not
    for start_idx in [0, 1]:
        bits = ""
        for val in vals[start_idx:]:
            if val < 0.0004:
                bits += "0"
            else:
                bits += "1"
        
        print(f"\n--- Start Index: {start_idx} ---")
        
        # 0=0.15, 1=0.65
        print("0=0.15, 1=0.65, MSB:")
        print(bits_to_bytes(bits))
        print("0=0.15, 1=0.65, LSB:")
        print(bits_to_bytes_rev(bits))
        
        # Inverted
        inverted_bits = "".join('1' if b == '0' else '0' for b in bits)
        print("0=0.65, 1=0.15, MSB:")
        print(bits_to_bytes(inverted_bits))
        print("0=0.65, 1=0.15, LSB:")
        print(bits_to_bytes_rev(inverted_bits))

if __name__ == "__main__":
    decode_deltas("deltas.txt")
