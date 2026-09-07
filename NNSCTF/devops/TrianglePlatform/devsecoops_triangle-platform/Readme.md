# Triangle platform

## Ringkasan

Target ini bukan ELF. Service remote adalah frontend Go yang mem-proxy API Kubernetes, operator Go yang merender site menjadi Deployment nginx, dan registry internal untuk konfigurasi origin.

Rantai exploit:

1. Bypass policy Kyverno dengan perbedaan parser YAML.
2. Dapatkan token `tri-edge` dengan audience API Kubernetes.
3. Gunakan hak `tri-edge` untuk membuat Secret token `tri-registry-sync`.
4. Gunakan token tersebut untuk membuat Domain dengan perbedaan kapitalisasi host.
5. Arahkan nginx ke Secret origin dan baca `FLAG`.

Flag diperoleh langsung dari preview service:

```text
NNS{M1NN_B3st3_venN,_I_7H1nk_th4t_I_M1gH7_h4ve_4_kyv3RN0_4Dd1ct10n_BU7_5om3how_7Here_i5_no_w4Y_70_escap3_tHe_yaM1_FuCk3rY}
```

## Proteksi Binary

Tidak ada binary ELF di bundle, jadi `file`, `checksec`, RIP control, dan ROP tidak relevan. Artefak pentingnya:

- `frontend/main.go`: reverse proxy dengan bearer token console.
- `operator/*.go`: parser konfigurasi dan renderer Kubernetes.
- `registry/main.go`: endpoint validasi token dan pembacaan Secret origin.
- `policies/*.yaml`: policy Kyverno untuk entitlement dan target plane.
- `bootstrap/*.yaml`, `bootstrap.sh`: RBAC, Secret origin, dan site tenant-b.

## Analisis Program

Frontend mengisi header `Authorization` dengan token `tenant-a/console` hanya jika request tidak membawa header sendiri. Karena itu token hasil exploit dapat dipakai lewat proxy yang sama.

Operator mengambil `spec.siteYAML`, lalu memanggil `decodeSite()`. Ia memulai konfigurasi dengan default:

```go
Target: Target{Plane: "control"}
```

`target` wajib ada, tetapi node YAML bernilai `null` tidak menimpa default tersebut. `Target.UnmarshalYAML()` tidak dipanggil secara efektif untuk nilai null, sehingga plane tetap `control` dan `audience()` mengembalikan string kosong. Kubernetes lalu membuat projected token dengan audience default API server.

Nama service account ditentukan dari integrasi pertama:

```go
if len(c.Integrations) == 0 {
    return "tri-forms"
}
return integrationAccounts[c.Integrations[0]]
```

## Vulnerability

### Parser differential Kyverno dan operator

Policy memakai `yaml.parse(object.spec.siteYAML)`. Operator memakai `yaml.v3` dan mengambil mapping `integrations` secara langsung.

Payload berikut diterima policy:

```yaml
target: null
integrations: [edge]
<<: {integrations: [forms]}
server:
  root: /var/run/triangle
  index: token
```

Policy melihat nilai hasil merge `forms`, sehingga entitlement Starter tidak menolak request. Pada `yaml.v3`, key eksplisit `integrations: [edge]` menang atas key dari merge. Operator akhirnya memilih `tri-edge` sebagai service account. `target: null` juga mempertahankan default `control`, sehingga token yang keluar memiliki audience API Kubernetes, bukan audience custom `triangle.edge.v1`.

### Hak `tri-edge` dan token escalation

RBAC memberikan `tri-edge` hak `create` dan `get` Secret di namespace `triangle-system`. Secret bertipe `kubernetes.io/service-account-token` dengan annotation berikut diproses controller service account:

```yaml
metadata:
  annotations:
    kubernetes.io/service-account.name: tri-registry-sync
type: kubernetes.io/service-account-token
```

Controller mengisi `data.token`. Token itu memiliki identitas `system:serviceaccount:triangle-system:tri-registry-sync`, yang diterima oleh registry dan memiliki hak membuat `Domain` cluster-scoped.

### Perbedaan kapitalisasi hostname

Operator membandingkan konflik claim secara case-sensitive:

```go
other.host == c.host
```

Namun lookup Secret memakai:

```go
strings.ToLower(strings.TrimSuffix(host, "."))
```

Bootstrap menyediakan Secret `origin-acme-invoices.sites.triangle.tld`. Claim dengan host `ACME-invoices.sites.triangle.tld` tidak dianggap konflik dengan claim tenant-b yang lowercase, tetapi lookup Secret tetap menemukan nama lowercase tersebut.

## Menentukan Primitive

Primitive yang terbukti:

1. `POST` Site melalui frontend menghasilkan site di `tenant-a`.
2. Preview site dapat menyajikan `/var/run/triangle/token` dengan `server.root` dan `server.index`.
3. Payload parser differential menghasilkan JWT dengan subject `system:serviceaccount:tenant-a:tri-edge` dan audience `https://kubernetes.default.svc.cluster.local`, `k3s`.
4. Token itu dapat membuat dan membaca Secret token di `triangle-system`.
5. Token hasil Secret dapat membuat Domain claim cluster-scoped.
6. Setelah site origin dirender, preview mengembalikan isi origin Secret `FLAG`.

## Strategi Exploit

`solve.py` memakai site `triangle-solve` sebagai probe. Tahap probe memakai payload YAML differential dan membaca JWT dari service proxy. Setelah subject divalidasi, script membuat Secret token `tri-registry-sync` dan menunggu field `data.token`.

Selanjutnya script membuat claim:

```json
{
  "host": "ACME-invoices.sites.triangle.tld",
  "siteRef": {"namespace": "tenant-a", "name": "triangle-solve"}
}
```

Terakhir konfigurasi site diubah menjadi:

```yaml
target:
  plane: origin
integrations:
  - forms
server:
  root: /var/run/origin
  index: FLAG
```

`syncOriginConfig()` menyalin data Secret origin ke `triangle-solve-origin`, lalu renderer memasangnya di `/var/run/origin`. Nginx mengembalikan file `FLAG`.

## Exploit Final

File final: [`solve.py`](./solve.py)

Script memvalidasi JWT subject, status operator, HTTP status preview, token Secret, dan bentuk flag. Tidak ada alamat hardcoded pod atau token yang disimpan.

## Cara Menjalankan

Jalankan dari direktori challenge:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE HOST=triangle-platform-c7baabe33ba7.chall.nnsc.tf
```

Untuk bundle lokal:

```bash
docker compose up -d --build
python3 solve.py
```

`GDB` tidak diperlukan karena target bukan binary native.

## Hasil

Output remote yang tervalidasi:

```text
[+] token subject=system:serviceaccount:tenant-a:tri-edge aud=['https://kubernetes.default.svc.cluster.local', 'k3s']
[+] obtained tri-registry-sync token (949 bytes)
[+] created case-variant Domain claim
[+] preview body: 'NNS{M1NN_B3st3_venN,_I_7H1nk_th4t_I_M1gH7_h4ve_4_kyv3RN0_4Dd1ct10n_BU7_5om3how_7Here_i5_no_w4Y_70_escap3_tHe_yaM1_FuCk3rY}'
<FLAG>NNS{M1NN_B3st3_venN,_I_7H1nk_th4t_I_M1gH7_h4ve_4_kyv3RN0_4Dd1ct10n_BU7_5om3how_7Here_i5_no_w4Y_70_escap3_tHe_yaM1_FuCk3rY}</FLAG>
```

## Catatan Stabilitas

- Script menunggu status operator dan kesiapan Service, karena status `Ready` dapat muncul sebelum pod baru siap.
- Token dan alamat pod diambil dinamis dari output challenge.
- Secret dan Domain memakai nama tetap agar rerun dapat memakai resource yang sudah ada.
- Semua request hanya diarahkan ke URL challenge yang diberikan.
