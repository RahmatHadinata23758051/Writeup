import numpy as np, soundfile as sf, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
x,sr=sf.read('challenge.flac')
if x.ndim>1: x=x.mean(axis=1)

names=['C','C#','D','D#','E','F','F#','G','G#','A','A#','B']
chords=[]
for idx,seg in enumerate(np.array_split(x,4)):
    n=len(seg)
    X=np.abs(np.fft.rfft(seg*np.hanning(n)))
    freqs=np.fft.rfftfreq(n,1/sr)
    energy=np.zeros(12)
    for midi in range(36,85):
        f=440*2**((midi-69)/12)
        k=np.argmin(abs(freqs-f))
        lo=max(0,k-1); hi=min(len(X),k+2)
        energy[midi%12]+=np.max(X[lo:hi])**2
    best=None
    for root in range(12):
        for quality,ints,suffix in [('maj',(0,4,7),''),('min',(0,3,7),'m')]:
            triad=sum(energy[(root+i)%12] for i in ints)
            outside=(energy.sum()-triad)
            score=triad-0.08*outside
            cand=(score,names[root]+suffix)
            if best is None or cand[0]>best[0]: best=cand
    chords.append(best[1])
    print(idx, best, sorted([(energy[i],names[i]) for i in range(12)], reverse=True)[:5])
print('progression', chords)

N=16384
phase=np.angle(np.fft.fft(x[:N]))
bits=(phase[1:]<0).astype(np.uint8)
def to_bytes(b):
    return bytes(np.packbits(b,bitorder='big'))
bitlen=int.from_bytes(to_bytes(bits[:32]),'big')
payload=to_bytes(bits[32:32+bitlen])
print('bitlen',bitlen,'payload',len(payload),payload.hex())
key_material='-'.join(chords)
key=hashlib.sha256(key_material.encode()).digest()
iv,ct=payload[:16],payload[16:]
d=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor()
padded=d.update(ct)+d.finalize()
unpad=PKCS7(128).unpadder(); pt=unpad.update(padded)+unpad.finalize()
print(key_material, key.hex(), pt)
