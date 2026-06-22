from pwn import *

# Encoded strings for AlphaCode:
# 'Hello I am ': zpaa zzta zzzb zzzb zzze aaaa zqaa aaaa zzpa zzzc aaaa
# ', and I like ': maaa aaaa zzpa zzzd zzsa aaaa zqaa aaaa zzzb zzxa zzza zzta aaaa
# '.': oaaa
# 'I hate ': zqaa aaaa zzwa zzpa zzzj zzta aaaa

solve_ac = """zm a
zpaa zzta zzzb zzzb zzze aaaa zqaa aaaa zzpa zzzc aaaa
zm b
maaa aaaa zzpa zzzd zzsa aaaa zqaa aaaa zzzb zzxa zzza zzta aaaa
zm c
oaaa
zm d
zqaa aaaa zzwa zzpa zzzj zzta aaaa
zz fi
zz fi
zz di
a
zz fr
zz fi
zz fr
zz di
b
zz fr
zz dp
zz dp
zz dp
zz fr
zz di
c
zz fo
zz di
d
zz fr
zz dp
zz dp
zz dp
zz fr
zz di
c
zz fo
ex
"""

r = remote('po812e1n90q6.boroctf.com', 58298)
r.sendlineafter(b'[2] Enter the gauntlet\n', b'2')
r.sendlineafter(b'Enter your snippet: (Enter twice to finish!)\n', solve_ac.encode())
r.sendline(b'')

print(r.recvall().decode())
