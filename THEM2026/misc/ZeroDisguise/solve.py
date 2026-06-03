with open('falg.txt', 'r') as f:
    d = f.read().strip().split()
b = ''.join(['1'*len(d[i+1]) if d[i]=='0' else '0'*len(d[i+1]) for i in range(0, len(d), 2)])
# Biasanya Chuck Norris cipher menggunakan 7-bit ASCII
print(''.join([chr(int(b[i:i+7], 2)) for i in range(0, len(b), 7)]))
