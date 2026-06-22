import subprocess

def get_timestamps(pcap_file):
    # Extract relative timestamps of all SYN packets
    cmd = ["tshark", "-r", pcap_file, "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "-T", "fields", "-e", "frame.time_relative"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    timestamps = [float(t) for t in result.stdout.strip().split('\n')]
    return timestamps

def solve():
    timestamps = get_timestamps("chall.pcap")
    delays = []
    # Calculate intervals between consecutive packets
    for i in range(1, len(timestamps)):
        delays.append(round(timestamps[i] - timestamps[i-1], 2))
    
    # Map delays to bits: 0.75 -> 1, 0.25 -> 0
    bits = "".join(['1' if d == 0.75 else '0' for d in delays])
    
    # The encoding is "bilingual" (7-bit and 8-bit)
    # The first character is 7 bits, subsequent characters are 8 bits (usually 0 + 7 bits)
    flag = ""
    # First 7 bits
    flag += chr(int(bits[:7], 2))
    
    # Rest are 8-bit blocks
    for i in range(7, len(bits) - 7, 8):
        byte_val = int(bits[i:i+8], 2)
        flag += chr(byte_val)
    
    print(flag)

if __name__ == "__main__":
    solve()
