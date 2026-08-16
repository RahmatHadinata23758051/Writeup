import zipfile, random, calendar, time
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = bytes.fromhex(open("enc.txt").read().strip())

zf = zipfile.ZipFile("chall.zip")
# pakai timestamp enc.txt dari metadata zip
dt = zf.getinfo("enc.txt").date_time
y,mo,d,h,mi,s = dt
print("[*] zip enc.txt time:", dt)

def try_seed(seed):
    random.seed(seed)
    key = random.randbytes(32)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        return None
    if all(32 <= b < 127 or b in b"\r\n\t" for b in pt):
        return pt
    return None

# ZIP tidak simpan timezone secara pasti, jadi coba UTC offset -12..+14
base_naive = datetime(y, mo, d, h, mi, 0)
hits = []
for off in range(-12, 15):
    tz = timezone(timedelta(hours=off))
    base = base_naive.replace(tzinfo=tz)
    epoch0 = int(base.timestamp())
    for sec in range(60):
        seed = epoch0 + sec
        pt = try_seed(seed)
        if pt:
            hits.append((seed, off, pt))

for seed, off, pt in hits:
    print(f"[+] seed={seed} utc_offset={off:+03d}:00")
    print(pt.decode(errors="replace"))
