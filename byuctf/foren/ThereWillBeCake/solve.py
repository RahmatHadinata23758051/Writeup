import subprocess
import base64
import binascii

def get_flag_cake(pcap_file):
    try:
        cmd = ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields", "-e", "http.cookie"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip().split('\n')
        for line in output:
            if 'cake=' in line:
                b64_str = line.split('cake=')[1]
                return base64.b64decode(b64_str).decode()
    except Exception as e:
        pass
    return None

def get_flag_still_there(pcap_file):
    try:
        cmd = ["tshark", "-r", pcap_file, "-Y", "icmp.type == 8", "-T", "fields", "-e", "data.data"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
        hex_data = output.replace('\n', '')
        if hex_data:
            return binascii.unhexlify(hex_data).decode()
    except Exception as e:
        pass
    return None

def get_flag_paradox(pcap_file):
    try:
        cmd = ["tshark", "-r", pcap_file, "-Y", "ntp", "-T", "fields", "-e", "udp.payload"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip().split('\n')
        flag = ""
        for line in output:
            if line:
                payload_bytes = binascii.unhexlify(line)
                # Karakter disembunyikan di LSB (Least Significant Byte) dari bagian integer setiap timestamp NTP
                for idx in [19, 27, 35, 43]:
                    if payload_bytes[idx] != 0:
                        flag += chr(payload_bytes[idx])
        return flag
    except Exception as e:
        pass
    return None

def get_flag_corrupted(pcap_file):
    try:
        cmd = ["tshark", "-r", pcap_file, "-Y", "icmp.type == 8", "-T", "fields", "-e", "ip.src"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip().split('\n')
        b64_flag = ""
        for ip in output:
            if ip:
                octets = ip.split('.')
                for octet in octets:
                    if int(octet) != 0:
                        b64_flag += chr(int(octet))
        
        # Tambahkan padding jika kurang
        b64_flag += "=" * ((4 - len(b64_flag) % 4) % 4)
        return base64.b64decode(b64_flag).decode()
    except Exception as e:
        pass
    return None

if __name__ == "__main__":
    pcap = "chall.pcapng"
    print(f"[*] Extracting flags from {pcap}...\n")
    print(f"[+] There Will Be Cake: {get_flag_cake(pcap)}")
    print(f"[+] Are You Still There?: {get_flag_still_there(pcap)}")
    print(f"[+] Alright. Paradox Time: {get_flag_paradox(pcap)}")
    print(f"[+] Corrupted Cores: {get_flag_corrupted(pcap)}")
