import pyshark
import base64
import sys

def solve():
    try:
        # Filter only ICMP echo requests
        cap = pyshark.FileCapture('chall.pcapng', display_filter='icmp.type==8')
        b64_str = ""
        
        for pkt in cap:
            if hasattr(pkt, 'ip'):
                # Extract the source IP string
                ip_src = pkt.ip.src
                
                # Convert each IP octet to an ASCII character
                for octet in ip_src.split('.'):
                    b64_str += chr(int(octet))
                    
        cap.close()
        
        # Decode the gathered base64 string
        flag = base64.b64decode(b64_str).decode('utf-8').strip('\x00')
        print(f"<FLAG>{flag}</FLAG>")
        
    except Exception as e:
        print(f"Error occurred: {e}", file=sys.stderr)

if __name__ == '__main__':
    solve()
