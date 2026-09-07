# J*B Online Assessment

## Ringkasan

Service meminta upload activity Cisco Packet Tracer `.pka` yang selesai 100%.
File yang diunduh adalah PKA modern dengan payload XML yang dienkripsi.

## File Challenge

- `job-oa.pka` — activity asli dari endpoint download.
- `solve.py` — decoder, patcher, encoder, dan uploader opsional.

## Analisis Awal

Halaman web hanya memvalidasi nama file `.pka` dan ukuran maksimal 8 MiB.
Verifier sebenarnya berada di `POST /api/submit`. Upload file asli menghasilkan:

```text
Relay incomplete: 18/122 signed configuration markers recovered.
```

PKA bukan ZIP biasa. Format modernnya dapat dibalik dengan pipeline zlib,
XOR posisi, Twofish-EAX, lalu XOR/reversal posisi.

## Temuan Penting

Setelah didekripsi, XML memiliki tiga elemen `PACKETTRACER5` dan blok
`COMPARISONS` yang menjadi dasar penilaian 122 marker oleh service. Snapshot pertama adalah
network aktif yang dinilai, sedangkan snapshot ketiga berisi network target
yang cocok dengan struktur comparison tree.

## Proses Ekstraksi

`solve.py` melakukan hal berikut:

1. Mendekripsi `job-oa.pka` menjadi XML.
2. Mengambil `NETWORK` dari snapshot pertama dan ketiga.
3. Mengganti network aktif dengan deep copy network snapshot ketiga.
4. Mengenkripsi XML kembali menjadi `completed.pka`.
5. Jika diberi `--submit`, mengirim file tersebut ke `/api/submit`.

## Solve Script

Codec PKA disimpan di folder `pka-tools/pka2xml`. Folder ini berasal dari
implementasi open-source generik format PKA dan hanya dipakai untuk operasi
decode/encode lokal.

## Cara Menjalankan

Jika folder codec belum ada:

```bash
git clone --depth 1 https://github.com/jeamxn/cisco-pka-to-xml.git pka-tools
python3 pka-tools/build_libtwofish.py
```

```bash
python3 solve.py
python3 solve.py --submit
```

Atau gunakan URL challenge lain yang memang diberikan sebagai target:

```bash
python3 solve.py --submit --url "$HOST_URL"
```

## Flag

```text
TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026}
```

## Catatan

Validasi akhir dari service:

```json
{"ok":true,"matched":122,"required":122}
```
