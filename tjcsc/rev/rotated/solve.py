import os
import subprocess
import base64
import gzip
import io

# 1. Decrypt the binary
with open('chall', 'rb') as f:
    data = f.read()

# The binary is Caesar shifted by 0x1d
decrypted = bytes([(b - 0x1d) % 256 for b in data])

with open('chall_dec', 'wb') as f:
    f.write(decrypted)

os.chmod('chall_dec', 0o755)

# 2. Run the decrypted binary to get script.sh
# It will drop script.sh in the current directory
try:
    subprocess.run(['./chall_dec'], check=True, capture_output=True)
except Exception as e:
    print(f"Error running binary: {e}")

if not os.path.exists('script.sh'):
    print("Error: script.sh not created")
    exit(1)

# 3. Read script.sh
with open('script.sh', 'r') as f:
    script_content = f.read()

# Extract the base64 string from the single quoted string starting with H4sI
import re
match = re.search(r"'(H4sI[^']+)'", script_content)
if not match:
    print("Error: base64 string not found in script.sh")
    exit(1)

b64_str = match.group(1)

# 4. Decode the first layer (Gzip-compressed script)
compressed_data = base64.b64decode(b64_str)
with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as f:
    inner_script = f.read().decode()

# The inner script content is: echo "Looking for a flag?" # dGpjdGZ7YjQ1aF9kM2J1Nl9tNDU3M3J9Cg==
# 5. Extract and decode the flag from the comment
flag_b64 = inner_script.split('#')[-1].strip()
flag = base64.b64decode(flag_b64).decode().strip()

print(f"<FLAG>{flag}</FLAG>")

# Cleanup
if os.path.exists('chall_dec'): os.remove('chall_dec')
if os.path.exists('script.sh'): os.remove('script.sh')
