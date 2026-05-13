def solve_escalation():
    ciphertext = """Gtrq: JMX. Fb: Zlfbim Acus

Ws GST ceqrzhutmky.wf dmqnrcjkz


Tz cgtvj nj hcdp ws boap btevbv ISF xkprr, yh mgcm npovrtt lh bk ygebf anzo cblzfajjzfz 20% nf vki hhktoyp rsugsknhakr's gptqufmnc uahd dwfimu dnr ilfxuu'b RBH. Jygly sem vpnxryklz pzd hwyj kiga uhlm jiy h ykjdvgt.

KUH Qpzntoxxfzpww:

Om qtuxjoeke RBO xwguaveemgwdd qho wzadpu wlfz gxec fvdhk mymi kdmptb bost lp hgtt xhl lombetulrl nqkczz'g glwkczo dnr urqj vn, zd oab gy tkrp wptnhfe. Hyf jwab tx hkscc uq hjvhzcwpzg B3D0kS1055L4DJ1R3 mwa adbqtijaga.

Rihphh:........ Sqkw:......."""

    decrypted = ""
    for i, char in enumerate(ciphertext):
        shift = i + 1  # Shift bertambah 1 setiap karakter (1-indexed)
        
        if 'a' <= char <= 'z':
            # Dekripsi huruf kecil
            new_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted += new_char
        elif 'A' <= char <= 'Z':
            # Dekripsi huruf besar
            new_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            decrypted += new_char
        else:
            # Karakter non-alfabet tetap dihitung dalam urutan shift tapi tidak diubah
            decrypted += char
            
    return decrypted

print(solve_escalation())
