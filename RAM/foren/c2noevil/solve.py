import subprocess
import base64

def solve():
    cmd = "tshark -r chall.pcap -Y 'dns.qry.type == 16' -T fields -e dns.qry.name"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()
    
    queries = stdout.decode().strip().split('\n')
    chunks = {}
    
    for q in queries:
        if '-' in q:
            part = q.split('.')[0]
            idx, val = part.split('-', 1)
            if idx not in chunks:
                chunks[idx] = val
    
    encoded_str = "".join([chunks[k] for k in sorted(chunks.keys())])
    
    padding = len(encoded_str) % 8
    if padding != 0:
        encoded_str += "=" * (8 - padding)
        
    flag = base64.b32decode(encoded_str.upper()).decode()
    print(flag)

if __name__ == "__main__":
    solve()
