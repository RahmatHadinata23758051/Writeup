import subprocess

def solve():
    # Run the binary and get the output
    try:
        result = subprocess.run(['./chall_extracted/satoshi_pulse_v2'], capture_output=True, text=True, timeout=5)
        output = result.stdout
    except Exception as e:
        print(f"Error running binary: {e}")
        return

    # Extract numbers from the output
    numbers = []
    for line in output.split('\n'):
        line = line.strip()
        if line.isdigit():
            numbers.append(int(line))

    if not numbers:
        print("No numbers found in output.")
        return

    # Cache Side Channel Analysis:
    # Low values (~200-900) = Cache Hit (0 bit)
    # High values (>10000) = Cache Miss (1 bit)
    binary = "".join(['0' if n < 2000 else '1' for n in numbers])
    
    # Convert binary to ASCII
    flag = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            flag += chr(int(byte, 2))
    
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
