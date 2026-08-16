# Nova Vault — forensic writeup

## Artefak

File yang diberikan:

- `NovaVault_DMP.dmp` — crash artifact KeePass.
- `NovaVault_DB.kdbx` — database KeePass.
- `ops-chat.log` — catatan operator.
- `sha256sums.txt` — checksum integritas.

Checksum pada `sha256sums.txt` cocok dengan database dan dump. `file` mengenali database sebagai KDBX, sedangkan dump memakai header `MDMP` tetapi bukan minidump Windows standar yang bisa langsung diproses Volatility.

## Petunjuk dari chat

Log memberi tiga petunjuk yang relevan:

1. Fokusnya adalah crash password manager.
2. Master key vault Nova selalu dimulai dengan `N`.
3. Field yang terlihat `REDACTED` tidak boleh dianggap sebagai credential yang sudah pulih.

Karena itu database tetap perlu dibuka menggunakan material dari crash artifact, lalu history entry harus diperiksa.

## Membaca struktur dump

String awal dump berisi telemetry berikut:

```text
NovaVault crash telemetry; process=KeePass.exe;
case=NVX-20260813-KPX; users=nova0x,aws,afaneh,omar,moh
```

Di bagian setelah metadata terdapat pola berulang:

```text
cf 25 <byte karakter> 00 00 00
```

Byte karakter di field ukuran record diulang tiga kali. Mengambil semua field tersebut dan melakukan run-length collapse menghasilkan:

```text
0va0x_Aws_MemorySplit_2026!x-Q4S
```

Bagian `x-Q4S` adalah trailing artifact setelah payload password. Bagian password yang konsisten dengan petunjuk chat adalah:

```text
N0va0x_Aws_MemorySplit_2026!
```

## Membuka database

Database dapat dibuka dengan password di atas. Entry yang tampak biasa berisi credential rotasi, nilai audit, atau placeholder. Entry penting bernama:

```text
vault-recovery-backdoor
```

Field password saat ini berisi:

```text
REDACTED-ROTATED-SEE-AUDIT-TRAIL
```

Namun entry tersebut memiliki satu history item. Password pada history item adalah nilai sebelum containment mengubah record yang terlihat, dan nilainya merupakan flag.

## Reproduksi

Jalankan:

```bash
python3 solve.py
```

Script mengambil karakter dari record dump, membentuk password KeePass, membuka KDBX, lalu mencari flag pada history entry.

## Flag

```text
Thryve{n0v40x_k33p4ss_m3m0ry_sh4rd5_l34k3d_th3_v4ult_k3y_wh1l3_4ws_4f4n3h_0m4r_4nd_m0h_ch4s3d_th3_r0t4t3d_h1st0ry_4cr0ss_th3_cr4sh_4rt1f4ct_2026}
```
