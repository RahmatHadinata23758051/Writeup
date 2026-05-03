with open('chall.txt', 'r') as f:
    data = f.read().split()

flag = "".join(chr(int(x)) for x in data)
print(flag)
