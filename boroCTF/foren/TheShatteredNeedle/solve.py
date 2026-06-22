import os
import re

def solve():
    fragments = {}
    pattern = re.compile(r"\[FLAG_FRAGMENT_(\d)/5\]: (.*) End\.")
    
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith(".txt"):
                path = os.path.join(root, file)
                with open(path, 'r') as f:
                    content = f.read()
                    match = pattern.search(content)
                    if match:
                        idx = int(match.group(1))
                        frag = match.group(2)
                        fragments[idx] = frag
                        
    flag = "".join(fragments[i] for i in sorted(fragments.keys()))
    print(flag)

if __name__ == "__main__":
    solve()
