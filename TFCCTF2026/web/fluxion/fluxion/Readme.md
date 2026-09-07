# FLUXION

## Ringkasan

Flag berada di output terenkripsi milik run `admin-provision-approval`. Jalur exploit memanfaatkan beberapa bug pada RPC publik, lalu memakai diagnostic report untuk membocorkan flag melalui pesan error.

## Target dan File

- Target: `http://fluxion-f4efe1f76cec3abf.challs.ctf.thefewchosen.com`
- Source lokal: `src/server.js`, `src/world.js`, `src/lib/fcp.js`, `src/prng.js`, dan modul RPC terkait.
- Solver: [solve.py](./solve.py)

## Analisis Awal

`world.seed()` membuat satu run privat bernama `admin-provision-approval`. Flag disimpan di `run._flag`, dan hanya dimasukkan ke output ketika hook privat di-resume dengan `approved: true`.

Run ID dan lima `stepId` dapat dibaca lewat endpoint publik. Approval nonce tidak ikut ditampilkan, tetapi masih dipakai oleh `searchRuns` sebagai field indeks.

## Source Code Review

`enrollDevice` membuat device viewer, lalu menjalankan `Object.assign(base, profile)`. Karena `profile` dikontrol user, `tier` dapat ditimpa menjadi `operator`. Token enrollment hasilnya ditandatangani server dan diterima oleh FCP.

`searchRuns` memasukkan `approvalNonce` ke daftar field yang boleh dicari dan secara khusus mengizinkan `$startsWith`. Hasil query hanya public run, tetapi jumlah hasil menjadi oracle untuk memulihkan 16 karakter nonce.

Hook privat dibuat setelah lima output LCG 24-bit. Lima `stepId` yang terekspos cukup untuk memulihkan state LCG dengan lattice/CVP, sehingga output 64-bit berikutnya (token hook privat) bisa dihitung.

## Vulnerability

Ada tiga bypass penting:

1. Privilege escalation pada `enrollDevice` melalui overwrite `profile.tier`.
2. Information leak pada `searchRuns` melalui prefix oracle `approvalNonce`.
3. `previewApprovalGrant` memeriksa action dengan regex pada raw JSON, sedangkan `JSON.parse` memakai duplicate key terakhir. Dokumen dengan `act: read` lalu `act: resume` lolos signer dan diverifikasi sebagai `resume`.

Selain itu, nginx menolak path lowercase `/fcp`, sedangkan route Express bersifat case-insensitive. POST ke `/FCP` mencapai control plane dan menghasilkan arm token setelah handshake.

## Eksploitasi

1. Enroll device dengan profile `tier=operator`.
2. Pulihkan `approvalNonce` karakter demi karakter memakai `$startsWith`.
3. Ambil lima event step privat dan recover token hook berikutnya dari LCG.
4. Jalankan HELLO, KEX, TICK, dan ARM pada `/FCP` untuk mendapatkan arm capability.
5. Buat approval grant dengan duplicate JSON key pada `act`, lalu panggil `resumeHook` dengan `approved=true`.
6. `saveViewPreferences` menerima nested `constructor.prototype`, sehingga `mergeDeep` menulis `presentation` ke `Object.prototype`.
7. Caption report diarahkan ke `${engine.runs.<runId>._flag}`. `renderCaption` menolak nilai non-numerik dan memasukkan nilai flag ke diagnostic error.

Request penting terakhir menghasilkan response:

```json
{
  "report": "render diagnostic",
  "diagnostic": "E_SCALAR: 'engine.runs.<runId>._flag' is not a renderable metric: TFC{5d7096f57f88723bfccc910121b7f9cd}"
}
```

## Solve Script

`solve.py` mengotomatisasi seluruh chain, termasuk CRC32 framing FCP, nonce oracle, pemulihan LCG, handshake, resume, prototype pollution, dan ekstraksi regex dari report.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Target dapat diganti tanpa scanning host lain:

```bash
TARGET="http://127.0.0.1:3000" python3 solve.py
```

Solver membutuhkan `requests` dan `fpylll`.

## Flag

`TFC{5d7096f57f88723bfccc910121b7f9cd}`

## Catatan Stabilitas

Nonce, run ID, dan token berubah setiap boot. Solver tidak meng-hardcode ketiganya; semuanya dipulihkan dari response challenge. FCP juga membaca delay dan jumlah rung dari response, sehingga tetap berjalan bila ladder dikalibrasi berbeda.
