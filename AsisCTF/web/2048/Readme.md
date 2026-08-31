# 2048

## Ringkasan

Flag berada di dua file berlabel acak pada `/opt/citadel/vault` dan
`/opt/citadel/gate`. Gateway TCP di port 4000 menerima frame Tomcat Tribes,
gagal memeriksa seal AES lalu meneruskan objek Java ke session keeper. Objek
Commons Collections menghasilkan RCE sebagai user `citadel`.

## Recon

`/robots.txt` menunjuk ke `/citadel/lab-notes.html`. Catatan tersebut memberi
port 4000, format AES/CBC, direktori vault/gate/shared, serta Commons
Collections 3.x. Endpoint `/diagnostics.jsp` hanya terbuka bila proxy header
dipalsukan:

```bash
curl -H 'X-Forwarded-For: 127.0.0.1' http://91.107.164.78:8080/diagnostics.jsp
```

Respons mengonfirmasi `commons-collections-3.2.1.jar` dan receiver Tribes di
`*:4000`.

## Vulnerability dan framing

Receiver memakai paket XByteBuffer: header `FLT2002`, panjang 4-byte big-endian,
data `ChannelData`, lalu footer `TLF2003`. `ChannelData` membawa payload
serialisasi Java. Validasi seal yang gagal tetap meneruskan data ke session
keeper; gadget map memicu `Runtime.exec` saat map diproses.

## Eksploitasi

Payload di `solve.py` menjalankan perintah shell yang menggabungkan:

```text
/opt/citadel/vault/* + /opt/citadel/gate/* -> /opt/citadel/shared/loot
```

Mirror mengambil shelf satu kali:

```bash
curl 'http://91.107.164.78:8080/mirror.jsp?parcel=loot'
```

Respons yang diperoleh:

```text
nothing to see here, Morty.ASIS{do_you_think_rick_sanchez_is_stupid?}ASIS{t0McAT_was_Th3_KEY}
```

String Rick adalah decoy. Flag valid yang lengkap adalah
`ASIS{t0McAT_was_Th3_KEY}`.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Gunakan `TARGET` untuk host alternatif dan `GATE_PORT` bila port gateway
berbeda. Solver menampilkan flag hanya setelah mirror mengembalikan response 200
yang berisi flag.

## Flag

`ASIS{t0McAT_was_Th3_KEY}`

