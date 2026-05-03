# Writeup - KubSTU CTF: TeamForge

## Deskripsi Challenge
TeamForge adalah platform kolaborasi tim dengan kontrol akses berbasis peran (Owner, Admin, Member). Kita diberikan akun Member biasa (`user@test.com`) dan tujuan kita adalah melakukan privilege escalation ke Admin atau Owner untuk mendapatkan flag yang ada di admin dashboard.

## Langkah-langkah Penyelesaian

### 1. Eksplorasi Awal
Pertama, saya login menggunakan kredensial yang diberikan: `user@test.com` / `password123`. Setelah masuk, saya melihat dashboard yang menunjukkan bahwa saya adalah Member di organisasi "Beta Labs". 

Saya mencoba mengakses beberapa endpoint sensitif seperti `/admin` atau `/org/2/settings`, namun mendapatkan error 404 atau 403 (Forbidden).

### 2. Menemukan Kerentanan (Broken Access Control)
Sambil menelusuri aplikasi, saya mencoba melakukan testing pada IDOR (Insecure Direct Object Reference) atau akses kontrol yang lemah. Saya menemukan bahwa endpoint `/org/1/team` dapat diakses meskipun saya bukan anggota dari organisasi tersebut (Org 1 - Acme Corp).

### 3. Kebocoran Informasi (Information Leakage)
Di halaman `/org/1/team`, terdapat bagian "Pending Invitations". Di sana terdapat komentar HTML yang cukup mencolok: `<!-- Pending Invitations - VULNERABLE: Email addresses are visible! -->`. 

Halaman tersebut menunjukkan bahwa ada satu undangan tertunda untuk email `victoria.chase@acme.com` dengan peran sebagai **Owner**.

### 4. Eksploitasi (Invitation Hijacking)
Karena sistem pendaftaran tidak memerlukan verifikasi email ("No verification required - your account will be active immediately!"), saya memanfaatkan informasi ini dengan cara:
1. Mendaftar akun baru menggunakan email `victoria.chase@acme.com`.
2. Setelah mendaftar dan login, saya melihat notifikasi di dashboard bahwa saya memiliki undangan tertunda untuk bergabung dengan "Acme Corp" sebagai Owner.
3. Saya menuju halaman `/invitations` dan menerima undangan tersebut.

### 5. Mengambil Flag
Setelah menerima undangan, akun saya kini memiliki akses penuh (Owner) ke organisasi "Acme Corp". Menu "Settings" pun muncul di sidebar.

Saya menelusuri pengaturan organisasi dan menemukan menu **Security** (`/org/1/settings/security`). Di halaman tersebut, terdapat bagian "Master API Key" yang menampilkan flag:

**Flag:** `KubSTU{21509994fd5a1383bfb6b4c4d85b4cf0}`

## Kesimpulan
Vulnerability utama dalam aplikasi ini adalah **Broken Access Control** pada halaman manajemen tim yang membocorkan alamat email dari undangan yang sedang tertunda. Dikombinasikan dengan sistem registrasi tanpa verifikasi, penyerang dapat mengambil alih peran (hijacking role) yang dimaksudkan untuk orang lain.
