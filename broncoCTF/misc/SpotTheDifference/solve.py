# Solve script for Spot The Difference
with open("file2.txt") as f2, open("file1.txt") as f1:
    chars1 = [line.strip('\r\n') for line in f1.read().splitlines()]
    chars2 = [line.strip('\r\n') for line in f2.read().splitlines()]

flag = []
for i in range(min(len(chars1), len(chars2))):
    c1 = chars1[i]
    c2 = chars2[i]
    if c1 != c2 and abs(ord(c1) - ord(c2)) != 32:
        flag.append(c2)
        if c2 == '}':
            break

print("".join(flag))
