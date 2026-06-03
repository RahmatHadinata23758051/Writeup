from PIL import Image
import random, re
im=Image.open('bacaro.png').convert('RGB')
flat=[c for px in im.getdata() for c in px]
term='1111111111111110'
def extract(seed, nbits=200000):
    pos=list(range(len(flat)))
    random.seed(seed)
    random.shuffle(pos)
    bits=''.join('1' if flat[p]&1 else '0' for p in pos[:nbits])
    j=bits.find(term)
    if j==-1:
        j=min(len(bits),2000)
    msgbits=bits[:j]
    return bytes(int(msgbits[k:k+8],2) for k in range(0,len(msgbits)-7,8)), j
seeds=['Aciugheta','ACIUGHETA','aciugheta','L Aciugheta',"L'Aciugheta","l'aciugheta",'l’Aciugheta','L’Aciugheta','La Aciugheta','Al Aciugheta','Osteria Aciugheta',"Osteria L'Aciugheta","Osteria l'aciugheta",'Osteria L’Aciugheta','Bacaro Aciugheta','Aciugheta Venezia','Laciugheta','laciugheta','LACIUGHETA','L’aciugheta','L’ACIUGHETA','AllAciugheta','Al Aciugheta Venezia']
for seed in seeds:
    b,j=extract(seed, 5000)
    printable=sum(32<=x<127 or x in (9,10,13) for x in b[:100])
    if printable>70 or b'{' in b or b'flag' in b.lower() or j<5000:
        print('\nSEED',repr(seed),'bits',j,'score',printable)
        print(b[:300])
