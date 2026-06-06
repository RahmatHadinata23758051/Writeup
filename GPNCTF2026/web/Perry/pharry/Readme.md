# Pharry Writeup

Target ini kelihatan sederhana, tapi ada dua lapisan yang bikin exploit-nya jalan:

1. `md5_file($file)` dan `file_get_contents($file)` menerima input path yang bebas.
2. Class `User` punya destructor yang menjalankan `system("rm ".$this->avatar_path);`.

Itu artinya, kalau kita bisa memaksa PHP meng-unserialize object `User`, kita dapat command injection lewat properti `avatar_path`.

## Source Analysis

File `index.php`:

```php
$file = $_GET['path'];
$res = md5_file($file);
if ($res == FALSE){
    file_put_contents("/tmp/remote_file.jpg",file_get_contents($file));
    $res = md5_file("/tmp/remote_file.jpg");
}
if ($res == 0xdeadbeef){
    echo "Congratulations! Here is not your flag: ".file_get_contents("flag.txt");
} else{
    echo $res;
}
```

Dan class `User`:

```php
class User {
    public $avatar_path;
    public $name;
    public $password;
    function __construct($name, $password) {
        ...
        system("touch ".$this->avatar_path);
    }
    function __destruct() {
        system("rm ".$this->avatar_path);
    }
}
```

Kunci utamanya:

- `phar://` bisa memicu unserialize metadata saat archive dibuka.
- Destructor `User` bisa dipakai buat eksekusi command.

## Idea

Kalau kita punya file PHAR yang metadata-nya berisi object `User`, lalu file itu dibaca lewat `phar://`, destructor akan jalan saat request selesai.

Supaya file PHAR itu ada di server target, saya pakai dua tahap:

1. Request pertama ke URL publik milik sendiri.
2. URL publik itu balas `404` di hit pertama, lalu `200` di hit kedua.
3. Karena `md5_file()` ke URL itu gagal, kode masuk ke branch `file_get_contents()`.
4. Hit kedua ngirim bytes PHAR asli, jadi server menulisnya ke `/tmp/remote_file.jpg`.
5. Request kedua ke target pakai `phar:///tmp/remote_file.jpg/x.txt`.
6. Metadata PHAR di-unserialize, destructor `User` dieksekusi, dan command injection jalan.

## Payload

Properti `avatar_path` diisi string seperti:

```sh
x;cat /flag;#
```

Jadi destructor menjalankan:

```sh
rm x;cat /flag;#
```

Output `cat /flag` muncul di response.

## Hasil

Flag yang keluar:

```text
02129bb861061d1a052c592e2dc6b383GPNCTF{We8_15_f0r_wEe85_4ND_SUck5_phP_1s_coo1_tOugh}
```

## Catatan

- Endpoint publik saya pakai tunnel ke server lokal sendiri.
- PHAR bytes digenerate dengan `php -d phar.readonly=0`.
- Kode bantu exploit ada di [exploit.py](/home/nata/ctf/GPNCTF2026/web/Perry/pharry/exploit.py).
