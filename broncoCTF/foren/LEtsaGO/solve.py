import os

def solve():
    parts = {}
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.startswith(".part_"):
                try:
                    num = int(file.split(".part_")[1])
                    parts[num] = os.path.join(root, file)
                except ValueError:
                    pass
    
    combined = bytearray()
    for i in range(250):
        with open(parts[i], "rb") as f:
            combined.extend(f.read())
            
    content = combined.decode("utf-8", errors="ignore")
    flag = content.split("}")[0] + "}"
    print(flag)

if __name__ == "__main__":
    solve()
