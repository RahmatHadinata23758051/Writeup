# Writeup - Transmission from 1993 (Forensic)

Challenge ini kelihatan seperti suara modem/fax dari judul dan deskripsi:

`REEEEEE–KRRR–SKREEEEEE–BEEP BEEP BEEP`

Awalnya saya kira cukup dari RTP audio, tapi ternyata inti flag ada di dokumen fax yang ditransmisikan lewat **T.38**.

## 1) Recon awal

Artefak hanya satu file:

- `call-69e26052e9f5b0c1da0ee369.pcap`

Cek cepat:

```bash
file call-69e26052e9f5b0c1da0ee369.pcap
capinfos call-69e26052e9f5b0c1da0ee369.pcap
```

Hasil penting:

- capture type: Linux cooked (SLL)
- 1129 paket
- trafik utama: SIP + RTP + T.38

## 2) Triage protokol (SIP / RTP / T.38)

Statistik protokol:

```bash
tshark -r call-69e26052e9f5b0c1da0ee369.pcap -q -z io,phs
```

Terlihat:

- SIP signaling
- RTP voice
- T.38 (fax over IP)

Lalu cek SIP call flow:

```bash
tshark -r call-69e26052e9f5b0c1da0ee369.pcap -Y sip -T fields -e frame.number -e sip.Method -e sip.Status-Code
```

Ada **re-INVITE** dari audio ke `m=image ... udptl t38`, artinya memang switch ke fax session.

## 3) Cek decode T.38 dari tshark

Dari decode tshark, terlihat frame-frame T.30 seperti:

- NSF
- CSI
- TSI
- DCS
- CFR
- FCD (facsimile coded data)
- PPS
- MCF
- DCN

Artinya session fax berjalan komplet, bukan noise kosong.

## 4) Kendala tool bawaan

Tool standar (`tshark` field dump + `g3topbm`) belum langsung bisa membentuk page clean karena format dan framing T.38/ECM perlu decoder yang lebih proper.

Saya lanjut compile decoder dari source `spandsp` secara lokal (tanpa root), lalu jalankan decode terhadap stream T.38 yang tepat.

## 5) Decode fax pakai `t38_decode`

Jalankan decoder dengan endpoint T.38:

- src `192.168.0.199:38070`
- dst `23.179.16.198:34654`

Decoder menghasilkan:

- `t38pcap.tif`

Metadata TIFF menunjukkan dokumen fax valid (bi-level Group 3) dan transfer selesai sukses.

## 6) OCR hasil fax

Dokumen TIFF di-OCR, dan muncul teks yang memuat flag:

`CIT{fL3x_YOur_F4xiNG}`

## 7) Flag

`CIT{fL3x_YOur_F4xiNG}`

---

## File penting di folder ini

- `solve.py` -> otomatis decode + OCR + print `<FLAG>...`.
- `spandsp_src/tests/t38pcap.tif` -> hasil decode fax.

Cara pakai solve otomatis:

```bash
python3 solve.py
```

Output:

```text
<FLAG>CIT{fL3x_YOur_F4xiNG}</FLAG>
```
