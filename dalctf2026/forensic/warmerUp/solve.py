import re
import base64
import os
import subprocess

def solve():
    pdf_path = 'rules2.pdf'
    zip_path = 'extracted.zip'
    password = 'teapot_2026'
    sif_path = 'image.sif'
    
    # 1. Extract chunks from PDF
    print("[*] Extracting chunks from PDF...")
    with open(pdf_path, 'rb') as f:
        content = f.read().decode('latin-1')
    
    chunks = {}
    pattern = re.compile(r'@@(\d+):')
    matches = list(pattern.finditer(content))
    for i in range(len(matches)):
        chunk_id = int(matches[i].group(1))
        start = matches[i].end()
        if i + 1 < len(matches):
            end = matches[i+1].start()
            sub_content = content[start:end]
            stream_end = sub_content.find('endstream')
            if stream_end != -1:
                end = start + stream_end
            else:
                dict_end = sub_content.find('>>')
                if dict_end != -1:
                    end = start + dict_end
        else:
            end = content.find('endstream', start)
        
        data = content[start:end]
        data = re.sub(r'[^A-Za-z0-9+/=]', '', data)
        chunks[chunk_id] = data

    sorted_ids = sorted(chunks.keys())
    full_base64 = "".join(chunks[i] for i in sorted_ids)
    
    # Handle potential base64 length issues
    missing_padding = len(full_base64) % 4
    if missing_padding == 1:
        full_base64 = full_base64[:-1]
    elif missing_padding > 1:
        full_base64 += '=' * (4 - missing_padding)
        
    decoded_zip = base64.b64decode(full_base64)
    with open(zip_path, 'wb') as f:
        f.write(decoded_zip)
    print(f"[+] Reassembled ZIP saved to {zip_path}")

    # 2. Extract image.sif from ZIP
    print("[*] Unzipping ZIP...")
    subprocess.run(['unzip', '-P', password, '-o', zip_path], check=True)
    print(f"[+] Extracted {sif_path}")

    # 3. Extract SquashFS from SIF
    print("[*] Extracting SquashFS from SIF...")
    # Offset found from binwalk: 36864
    subprocess.run(['unsquashfs', '-f', '-d', 'squashfs-root', '-o', '36864', sif_path], check=True)
    
    # 4. Read flag
    flag_path = 'squashfs-root/home/flag/flag.txt'
    if os.path.exists(flag_path):
        with open(flag_path, 'r') as f:
            flag = f.read().strip()
            print(f"\n[!] FLAG: {flag}")
    else:
        print("[-] Flag not found in extracted filesystem.")

if __name__ == "__main__":
    solve()
