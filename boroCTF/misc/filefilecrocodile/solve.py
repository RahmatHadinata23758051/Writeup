import zipfile
import io

def solve():
    with open('chall.png', 'rb') as f:
        data = f.read()
    
    # ZIP data starts after PNG IEND chunk
    iend_pos = data.find(b'IEND') + 8
    zip_data = data[iend_pos:]
    
    # Repair signatures: FC -> PK
    fixed_zip_data = zip_data.replace(b'\x46\x43', b'\x50\x4b')
    
    # Load ZIP from memory
    z = zipfile.ZipFile(io.BytesIO(fixed_zip_data))
    
    # Password is 'croc'
    try:
        flag = z.read('flag.txt', pwd=b'croc').decode()
        print(f"Flag found: {flag}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve()
