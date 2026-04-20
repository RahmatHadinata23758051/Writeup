#!/usr/bin/env python3

def rot47(text):
    res = []
    for c in text:
        # Hanya memutar karakter ASCII yang *printable*
        if 33 <= ord(c) <= 126:
            res.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)

def rot13(text):
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

def main():
    cipher_part1 = "*@F 92G6 7@F?5 :E] ~FC DFCG6:==2?46 E62> :?E6C46AE65 2 EC2?D>:DD:@? 7C@> :?D:56 E96 %C256':D@C ?6EH@C<] %96 286?E FD65 2 4:A96C E@ AC@E64E E96 >6DD286] qFE 42? J@F 564CJAE E96 D64@?5 >6DD286n |2J36 ECJ FD:?8 D@>6 D@CE @7 #~% 564CJAE:@? 2D H6==]"
    cipher_part2 = "{39 F?:C @63IC2 G283 8FC v6?BCxG736 2C8;36I ?2B F?:C 6CACG:CB 8FC DJ?E] vFC DJ?E G7 HA8DLcA@BA!_\"Al$#@B_(0$N"

    print("[*] Membongkar Paragraf 1 (ROT47 murni)...")
    plain1 = rot47(cipher_part1)
    print(f"-> {plain1}\n")

    print("[*] Membongkar Paragraf 2 (ROT47 + ROT13)...")
    # Dekripsi Lapis 1 (Buka cangkang ROT47)
    layer1 = rot47(cipher_part2)
    # Dekripsi Lapis 2 (Buka inti ROT13)
    plain2 = rot13(layer1)
    print(f"-> {plain2}\n")

    # Ekstrak Flag
    flag_start = plain2.find("jctf{")
    flag_end = plain2.find("}", flag_start) + 1
    if flag_start != -1:
        print("=" * 40)
        print(f"[!] BINGO! FLAG: {plain2[flag_start:flag_end]}")
        print("=" * 40)

if __name__ == "__main__":
    main()
