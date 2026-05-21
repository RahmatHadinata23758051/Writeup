import sys

def solve():
    data = open('chall.tsc', 'rb').read()
    pixels = []
    for i in range(16, len(data), 4):
        p = data[i:i+4]
        if len(p) == 4:
            pixels.append(p)
    
    from collections import Counter
    counts = Counter(pixels)
    bg = counts.most_common(1)[0][0]
    
    triplets = []
    for i, p in enumerate(pixels):
        if p != bg and not (p[1] == p[2] == p[3]):
            triplets.append((i, p[1], p[2], p[3]))
    
    flag = ""
    for i, r, g, b in triplets:
        for c in [r, g, b]:
            if 32 <= c <= 126:
                flag += chr(c)
    print(flag)

if __name__ == '__main__':
    solve()
