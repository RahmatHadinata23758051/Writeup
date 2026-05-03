import re

with open('message.txt', 'rb') as f:
    lines = f.readlines()

flag = ""
for line in lines:
    match = re.search(b'([ \t]+)\r?\n$', line)
    if match:
        ws = match.group(1)
        binary = ws.replace(b' ', b'0').replace(b'\t', b'1')
        if len(binary) == 8:
            flag += chr(int(binary, 2))
        else:
            # In case some lines have more or less than 8 bits
            # but let's see if 8 works for all first
            try:
                flag += chr(int(binary, 2))
            except:
                pass

print(flag)
