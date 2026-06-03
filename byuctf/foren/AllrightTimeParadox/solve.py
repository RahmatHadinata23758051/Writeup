import subprocess
import binascii

def main():
    cmd = ['tshark', '-r', 'chall.pcapng', '-Y', 'ntp', '-T', 'fields', '-e', 'udp.payload']
    output = subprocess.check_output(cmd).decode('utf-8').splitlines()
    flag = ""
    for line in output:
        payload = line.strip()
        if not payload:
            continue
        # NTP payload is usually 48 bytes
        # Look at the last 4 blocks of 8 bytes (4 * 8 = 32 bytes)
        # Actually it's 4 blocks of 6553f1XX00000000
        # The first 16 bytes are 23020a0000000000000000007f000001
        # Then we have 4 groups of 8 bytes: 6553f1 62 00000000
        # Let's just find the byte right after 6553f1
        parts = payload.split("6553f1")
        for part in parts[1:]:
            byte_hex = part[:2]
            if byte_hex != "00":
                flag += chr(int(byte_hex, 16))
    print(flag)

if __name__ == '__main__':
    main()
