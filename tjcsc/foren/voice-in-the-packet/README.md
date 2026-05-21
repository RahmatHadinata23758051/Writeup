# Writeup - voice-in-the-packet

Challenge ini kasih satu artefak: `call.pcap`.

## 1. Recon awal

Pertama saya cek isi folder dan tipe file:

```bash
ls -lah
file call.pcap
```

Hasilnya cuma ada satu file PCAP raw IPv4.

Lalu saya cari string yang mencurigakan:

```bash
strings -a call.pcap | rg -i "flag|ctf|tjc"
```

Keluar dua flag palsu:

- `tjctf{this_is_a_fake_flag_keep_looking}`
- `tjctf{definitely_not_the_real_flag}`

Jadi jelas ini sengaja dipasang buat ngecoh.

## 2. Lihat struktur trafik

Saya ringkas protokol dan endpoint:

```bash
tshark -r call.pcap -q -z io,phs
tshark -r call.pcap -q -z conv,ip
tshark -r call.pcap -T fields -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e udp.length | head
```

Temuannya:

- mayoritas trafik adalah UDP satu arah
- stream utama dari `192.168.1.100:10000` ke `192.168.1.200:20000`
- ada 1000 paket dengan panjang UDP konstan
- payload-nya kelihatan seperti RTP mentah

Header payload awal stream utama:

- version RTP valid
- sequence number naik satu-satu
- timestamp naik tetap
- SSRC konstan `0x12345678`

Jadi fokusnya saya pindahkan ke payload RTP.

## 3. Ekstrak payload stream utama

Saya buang header RTP 12 byte dan simpan payload mentah:

```bash
tshark -r call.pcap \
  -Y "ip.src==192.168.1.100 && udp.srcport==10000 && udp.dstport==20000" \
  -T fields -e data.data | awk '{print substr($0,25)}' | xxd -r -p > audio_payload.bin
```

Awalnya saya cek berbagai interpretasi audio, tapi itu cuma bikin noise atau tone dan tidak langsung memberi flag. Petunjuk penting justru muncul saat saya lihat bit-bit rendahnya.

## 4. Ambil LSB dari low byte sampel

Payload ternyata paling berguna kalau dibaca sebagai deretan sampel 16-bit little-endian, lalu diambil **byte rendah** dari tiap sampel, setelah itu ambil **LSB**-nya.

Script kecil yang saya pakai:

```python
from pathlib import Path

p = Path("audio_payload.bin").read_bytes()
low = p[0::2]
bits = ''.join(str(b & 1) for b in low)
packed = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))
Path("low_plane0_packed.bin").write_bytes(packed)
```

Setelah itu saya scan hasilnya:

```bash
strings -a low_plane0_packed.bin
xxd -g 1 -l 96 low_plane0_packed.bin
```

Di situ langsung kelihatan string base64 mulai offset `0x04`:

```text
dGpjdGZ7aDN5X3YwaXBfczczZ19pc180XzdoaW5nfQ==
```

Empat byte pertama cuma sampah/prefix:

```text
00 00 01 60
```

## 5. Decode base64

Terakhir tinggal decode:

```bash
python3 - <<'PY'
import base64
print(base64.b64decode("dGpjdGZ7aDN5X3YwaXBfczczZ19pc180XzdoaW5nfQ==").decode())
PY
```

Hasilnya:

```text
tjctf{h3y_v0ip_s73g_is_4_7hing}
```

## Flag

`tjctf{h3y_v0ip_s73g_is_4_7hing}`
