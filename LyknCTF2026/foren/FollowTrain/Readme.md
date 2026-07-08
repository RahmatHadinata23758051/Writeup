# Follow The Layer

**CTF:** LYKNCTF 2026  
**Category:** Forensics  
**Flag:** `LYKNCTF{7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab:03/21/2025:FUNNULL}`

## Deskripsi

> Our fraud response team flagged a suspicious USDT transfer linked to an online scam operation.
>
> The payment trail starts here:
>
> `d4500023a8114caaa640ab92bb8f73830a5303ccdfc4e9b0cf862bdae7ae336b`
>
> Trace the laundering chain, find where the money stops being attributable, and answer:
>
> - What is the transaction hash of the last traceable hop?
> - What date did it occur? (MM/DD/YYYY)
> - What is the name of the sanctioned entity at the heart of this operation?

## Ringkasan

Hash awal adalah transaksi TRC20 USDT di jaringan TRON. Dana dilacak sampai masuk ke hot wallet exchange berlabel `Bitget 9`.

```text
TXk7... --2700 USDT--> TNmR...
TNmR... --5222 USDT--> TQMq...
TQMq... --5222 USDT--> TJ7hh... [Bitget 9]
```

Nominal 5.222 USDT masih berpindah utuh pada hop terakhir. Setelah masuk `Bitget 9`, dana bercampur dengan transaksi pengguna lain sehingga atribusi individual berhenti.

## Analisis

### 1. Transaksi awal

```bash
curl -s \
  'https://apilist.tronscan.org/api/transaction-info?hash=d4500023a8114caaa640ab92bb8f73830a5303ccdfc4e9b0cf862bdae7ae336b' |
jq .
```

Hasil transfer:

```text
From   : TXk7Dor9GeRRpR5hbCGd4rBieM21v4BcwX
To     : TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8
Amount : 2,700 USDT
Date   : 02/27/2025
TXID   : d4500023a8114caaa640ab92bb8f73830a5303ccdfc4e9b0cf862bdae7ae336b
```

Wallet `TNmR...` terkait dengan sanctioned entity **FUNNULL**.

### 2. Outgoing dari TNmR

```bash
curl -sG 'https://apilist.tronscan.org/api/transfer/trc20' \
  --data-urlencode 'address=TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8' \
  --data-urlencode 'trc20Id=TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t' \
  --data-urlencode 'start=0' \
  --data-urlencode 'limit=50' \
  --data-urlencode 'direction=1' \
  --data-urlencode 'reverse=false' \
  --data-urlencode 'db_version=1' \
  --data-urlencode 'start_timestamp=1740661449000' |
jq -r '.data[] | [.block_timestamp, (.amount|tonumber/1000000), .from, .to, .hash] | @tsv'
```

Transfer yang relevan:

```text
TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8
    -> TQMq9s5eqxzHW9CG4hgrWxVZaz4oZDo3tb

Amount : 5,222 USDT
TXID   : 2ef09557180070d4bfd274f771619b062fa9a1dec5087869b45e65003256b9d9
```

### 3. Sweep ke Bitget

Wallet `TQMq...` meneruskan nominal yang sama hanya beberapa menit kemudian:

```text
From   : TQMq9s5eqxzHW9CG4hgrWxVZaz4oZDo3tb
To     : TJ7hhYhVhaxNx6BPyq7yFpqZrQULL3JSdb
Amount : 5,222 USDT
Date   : 03/21/2025
TXID   : 7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab
```

Detail transaksi mengandung label:

```json
{
  "addressTag": {
    "TJ7hhYhVhaxNx6BPyq7yFpqZrQULL3JSdb": "Bitget 9"
  }
}
```

### 4. Kenapa ini last traceable hop

Riwayat `TQMq...` menunjukkan pola deposit address exchange:

1. `Bitget 9` mengirim TRX untuk biaya gas.
2. Alamat deposit menerima USDT.
3. Seluruh USDT disapu ke `Bitget 9`.

Sesudah masuk hot wallet, terlihat banyak payout dengan nominal dan tujuan berbeda dalam hitungan detik. Dana sudah bercampur di pool exchange sehingga tidak ada pemetaan deterministik ke transaksi keluar tertentu.

Maka jawaban akhirnya:

```text
Hash   : 7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab
Date   : 03/21/2025
Entity : FUNNULL
```

## Solver

```bash
python3 solve.py
```

## Flag

```text
LYKNCTF{7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab:03/21/2025:FUNNULL}
```
