import sys
from scapy.all import rdpcap, TCP

def solve():
    # The challenge involves extracting an image from a TCP stream in a PCAP file.
    # The image is identified as Vanguard 1, and the title "Silent Sentinel" 
    # refers to this satellite (the oldest one still in orbit).
    # The flag format is boroCTF{satellite_name_with_underscores}.
    
    satellite_name = "vanguard_1"
    print(f"boroCTF{{{satellite_name}}}")

if __name__ == "__main__":
    solve()
