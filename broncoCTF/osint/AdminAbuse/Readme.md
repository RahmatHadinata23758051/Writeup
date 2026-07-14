# Admin Abuse

**Category:** OSINT / Discord  
**Flag:** `bronco{wh0_g4v3_th15_m4n_3d1t_pr1v1l3g35}`

## Challenge

Challenge hanya memberikan dua petunjuk:

```text
1160888390661714032
<t:1739660340:R>
```

Nilai pertama berbentuk Discord snowflake. Nilai kedua adalah format timestamp Discord.

Tujuannya adalah menemukan aktivitas administrator pada channel dan waktu yang dimaksud.

## 1. Mengenali Discord snowflake

ID:

```text
1160888390661714032
```

memiliki bentuk khas ID objek Discord. Ketika endpoint channel diperiksa, ID tersebut mengarah ke channel:

```text
announcements
```

dalam server BroncoCTF.

Request API:

```bash
curl -s \
  -H "Authorization: $AUTH" \
  'https://discord.com/api/v10/channels/1160888390661714032'
```

Struktur hasil penting:

```json
{
  "id": "1160888390661714032",
  "name": "announcements",
  "guild_id": "1160887571698700358"
}
```

URL channel dapat disusun sebagai:

```text
https://discord.com/channels/1160887571698700358/1160888390661714032
```

Jangan menaruh token Discord langsung di script atau writeup. Simpan secara lokal:

```bash
export AUTH='TOKEN_DISCORD'
```

## 2. Mengubah timestamp

Petunjuk kedua:

```text
<t:1739660340:R>
```

adalah Unix timestamp:

```text
1739660340
```

Konversi:

```bash
date -u -d @1739660340
```

Output mengarah ke:

```text
2025-02-15 22:59:00 UTC
```

Jadi kita harus mencari pesan di channel `announcements` sekitar waktu tersebut.

## 3. Membuat snowflake anchor

Discord API menerima parameter `around` berupa message snowflake, bukan Unix timestamp biasa.

Rumus snowflake Discord:

```text
snowflake = (timestamp_ms - 1420070400000) << 22
```

Contoh Python:

```python
timestamp = 1739660340
discord_epoch = 1420070400000

anchor = ((timestamp * 1000) - discord_epoch) << 22
print(anchor)
```

Setelah mendapatkan anchor, ambil pesan di sekitar waktu target:

```bash
CHANNEL='1160888390661714032'
AROUND='HASIL_SNOWFLAKE'

curl -s \
  -H "Authorization: $AUTH" \
  "https://discord.com/api/v10/channels/$CHANNEL/messages?around=$AROUND&limit=100" \
  | jq -r '.[] | [.id, .timestamp, .edited_timestamp, .author.username, .content] | @tsv'
```

## 4. Menemukan pesan yang diedit

Di sekitar waktu target terdapat pesan berikut:

```text
Message ID : 1340457542299549797
Created    : 2025-02-15T22:59:42.581000+00:00
Edited     : 2026-02-14T04:13:14.462000+00:00
Author     : yoshie (@yoshie878)
```

Isi pesan:

```text
Restarting
-# || bronco{wh0_g4v3_th15_m4n_3d1t_pr1v1l3g35} ||
```

Flag disembunyikan sebagai spoiler dan ditambahkan melalui edit jauh setelah pesan awal dibuat. Hal ini cocok dengan judul `Admin Abuse`: administrator memakai hak edit pada pesan announcement lama.

## Solver Sederhana

```python
#!/usr/bin/env python3
import os
import requests

CHANNEL_ID = "1160888390661714032"
TARGET_TS = 1739660340
DISCORD_EPOCH = 1420070400000

token = os.environ["AUTH"]
anchor = ((TARGET_TS * 1000) - DISCORD_EPOCH) << 22

response = requests.get(
    f"https://discord.com/api/v10/channels/{CHANNEL_ID}/messages",
    headers={"Authorization": token},
    params={"around": str(anchor), "limit": 100},
    timeout=20,
)
response.raise_for_status()

for message in response.json():
    content = message.get("content", "")
    if "bronco{" in content:
        print(content)
```

Run:

```bash
AUTH='TOKEN_DISCORD' python3 solve.py
```

Output relevan:

```text
bronco{wh0_g4v3_th15_m4n_3d1t_pr1v1l3g35}
```

## Flag

```text
bronco{wh0_g4v3_th15_m4n_3d1t_pr1v1l3g35}
```
