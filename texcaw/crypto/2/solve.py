parts = open("ciphertext.txt").read().rstrip("\n").split("\n\n")
text = "\n\n".join([parts[0], parts[1], parts[2]])

known_plain = """??????{??????????????????????????????????????????????????}

they know im here, and its only a matter of time before they find out who i am.
tell the general what the flag is as soon as possible.
tell the general before they find out where im hiding!
if all goes well, i'll meet you at our first meeting location tomorrow at midnight.
make sure you're not followed

p.s. the movie "imitation game" is very good. you should watch it when you can.
- john cairncross"""

period = 41
key = [None] * period
alpha_index = 0

for c, p in zip(text, known_plain):
    if c.isalpha():
        if p != "?":
            shift = (ord(c) - ord(p)) % 26
            key[alpha_index % period] = shift
        alpha_index += 1

if any(k is None for k in key):
    raise RuntimeError("key recovery incomplete")

out = []
alpha_index = 0
for ch in text:
    if ch.isalpha():
        shift = key[alpha_index % period]
        out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
        alpha_index += 1
    else:
        out.append(ch)

plaintext = "".join(out)
flag = plaintext.splitlines()[0]

print(plaintext)
print()
print(flag)
