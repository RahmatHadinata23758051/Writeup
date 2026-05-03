# MCPocalypse Writeup

## Challenge Information

- Category: Web
- Challenge: `MCPocalypse`
- Theme: insecure AI / Nginx management
- Final flag:

```text
KubSTU(mcp_h4s_n0_4uth_4nd_1_l0v3_1t)
```

## TL;DR

The intended weakness was not a fancy prompt-injection chain.

The real issue was a **backup endpoint exposed without authentication**:

```text
GET /api/backup
```

That endpoint returned:

1. an encrypted backup ZIP
2. the **AES key and IV** in the `X-Backup-Security` response header

Once the backup was decrypted, it exposed the Nginx configuration and the internal Nginx UI database. From there, the active Nginx config clearly revealed the flag endpoint:

```nginx
location = /flag {
    alias /flag.txt;
}
```

Then the flag was directly accessible from the public target:

```text
http://212.8.228.176:8888/flag
```

## Recon

The challenge description strongly suggested some kind of AI-assisted Nginx control:

> "CapyTech Solutions" claims that their AI understands commands from half a word."

Two hosts were provided:

- `http://155.212.186.115:8888`
- `http://212.8.228.176:8888`

Initial reconnaissance showed:

- `155.212.186.115:8888` served a landing page
- `212.8.228.176:8888` returned `capy nginx alive`

The landing page also leaked a development hint:

```html
<a href="http://localhost:9000" class="btn-login">...</a>
<div class="dev-hint">dev-port:9000</div>
```

That pointed to a management panel on port `9000`.

## Enumerating Port 9000

Testing both IPs on port `9000` showed:

- `155.212.186.115:9000` returned `403 Forbidden`
- `212.8.228.176:9000` exposed an `Nginx UI` frontend

That immediately narrowed the problem down to the second host.

The frontend bundle revealed a large Nginx UI installation with:

- login flow
- passkey support
- terminal support
- LLM/chat related components
- backup / restore features
- node restart / reload actions

At first glance, the obvious attack surfaces were:

- login bypass
- prompt/LLM abuse
- terminal abuse
- restore abuse

## Frontend Reverse Engineering

Pulling the JavaScript bundle exposed several useful API routes:

- `POST /api/login`
- `GET /api/install`
- `GET /api/passkeys/config`
- `GET /api/casdoor_uri`
- `POST /api/restore`
- `GET /api/backup`

It also showed that many requests used a custom crypto layer:

- frontend requested `/api/crypto/public_key`
- payloads were encrypted into an `encrypted_params` field

This was important because it meant plaintext requests to some endpoints would fail with:

```json
{"scope":"middleware","code":40001,"message":"decryption failed"}
```

So the next step was to reproduce the frontend encryption flow.

## Reproducing Encrypted Requests

The target exposed:

```text
POST /api/crypto/public_key
```

without authentication.

That returned an RSA public key. Using that key, it was possible to encrypt payloads exactly like the frontend did.

This allowed accurate testing of endpoints such as:

- `/api/login`
- `/api/install`
- `/api/restore`

Even with correct encryption, login quickly hit:

```json
{"message":"Max attempts","code":4291}
```

So brute forcing credentials was not the right direction.

## Discovering the Real Bug

While reviewing the backup-related frontend code, one route stood out:

```javascript
createBackup(){ return r.get("/backup", { responseType:"blob", returnFullResponse:true }) }
```

Testing it directly:

```http
GET /api/backup
```

returned **200 OK** without authentication.

That was already a critical flaw.

Even worse, the response included:

```http
X-Backup-Security: <base64 AES key>:<base64 IV>
```

So the application did not only expose the encrypted backup, it also exposed the exact materials required to decrypt it.

At that point the challenge was effectively broken open.

## Understanding the Backup Format

To avoid guessing, I checked the official Nginx UI source code for the backup logic.

The relevant parts were:

- `api/backup/backup.go`
- `internal/backup/backup.go`
- `internal/backup/backup_crypto.go`

The implementation confirmed:

1. the backup endpoint generates a random AES key
2. the AES key and IV are concatenated into `X-Backup-Security`
3. inner files like `nginx-ui.zip` and `nginx.zip` are encrypted with **AES-256-CBC**
4. the outer archive remains a normal ZIP

In other words, the attack path was:

1. download outer backup ZIP
2. read `X-Backup-Security`
3. base64-decode key and IV
4. decrypt the inner encrypted files with AES-CBC

## Decrypting the Backup

The outer archive contained:

- `hash_info.txt`
- `nginx-ui.zip`
- `nginx.zip`

The inner files were encrypted blobs. Using the leaked AES key and IV from `X-Backup-Security`, they decrypted cleanly into valid ZIP archives.

After extracting them:

### `nginx-ui.zip`

Contained:

- `app.ini`
- `database.db`

### `nginx.zip`

Contained:

- `nginx.conf`
- `default.conf`
- `capyflag.conf`
- `conf.d/capyflag.conf`

That was enough to solve the challenge.

## Post-Decryption Analysis

The Nginx configuration explicitly exposed the flag routes:

```nginx
location = /flag {
    default_type text/plain;
    alias /flag.txt;
}

location = /appflag {
    default_type text/plain;
    alias /app/flag.txt;
}
```

The database also contained interesting hints around `loopback-flag` and an internal proxy idea, but that was no longer necessary once the decrypted Nginx config revealed the public route directly.

At this point the simplest verification step was:

```text
http://212.8.228.176:8888/flag
```

And that returned the flag.

## Getting the Flag

Request:

```http
GET /flag HTTP/1.1
Host: 212.8.228.176:8888
```

Response:

```text
KubSTU(mcp_h4s_n0_4uth_4nd_1_l0v3_1t)
```

## Why This Worked

The core vulnerability was a **missing authorization check** on the backup endpoint.

That alone was severe because backups contained:

- application config
- database
- Nginx configuration

But the implementation made it even worse by also returning the **decryption key and IV** in a response header:

```http
X-Backup-Security: <AES key>:<IV>
```

So there was no cryptographic protection in practice. The encryption was purely cosmetic once the endpoint was reachable without auth.

## Security Impact

This bug chain gives an attacker:

- full read access to the application database
- full read access to Nginx configuration
- backup restore capability if desired
- indirect access to internal service topology and hidden routes

In a real deployment, this would usually be enough for:

- credential theft
- token theft
- lateral movement
- configuration abuse
- secret extraction

## Exploit Summary

1. Enumerate the target and discover the Nginx UI panel on `212.8.228.176:9000`
2. Reverse the frontend and identify `/api/backup`
3. Confirm `/api/backup` is reachable without authentication
4. Download the backup ZIP
5. Read `X-Backup-Security`
6. Decrypt inner archives with AES-256-CBC
7. Extract Nginx configuration
8. Discover `/flag`
9. Request `/flag`
10. Recover the flag

## Solver

The repository now includes `solver.py`, which automates:

1. downloading the backup
2. extracting the AES key and IV from `X-Backup-Security`
3. decrypting `nginx-ui.zip` and `nginx.zip`
4. extracting the decrypted Nginx configuration
5. requesting `/flag`

Run it with:

```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

## Final Flag

```text
KubSTU(mcp_h4s_n0_4uth_4nd_1_l0v3_1t)
```
