# バカ通信

File yang dikasih cuma satu image EWF:

```bash
rtk file idiot_communication.E01
```

Hasilnya EnCase/FTK image. Setelah di-mount lewat `ewfmount`, volume di dalamnya ternyata satu NTFS dan ada user `John Rich`.

```bash
mkdir -p ewf
rtk ewfmount idiot_communication.E01 ewf
rtk fsstat ewf/ewf1 | head
rtk fls ewf/ewf1 10411
```

Target challenge bilang kredensial GitHub ada di device ini, jadi fokusnya ke profil user. Repo di `Documents/repos/NOTTheFlag` cuma decoy. Yang kepakai justru file terhapus dari profil user.

```bash
mkdir -p recovered_user
rtk tsk_recover -e -d 10516 ewf/ewf1 recovered_user
```

Setelah recovery, cari token GitHub:

```bash
python3 - <<'PY'
from pathlib import Path
for p in Path('recovered_user').rglob('*'):
    if p.is_file() and p.stat().st_size < 5_000_000:
        try:
            data = p.read_bytes()
        except Exception:
            continue
        for needle in [b'github_pat_', b'ghp_']:
            if needle in data:
                print(p)
                break
PY
```

Hit penting muncul di cache WebView:

```text
recovered_user/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/LocalState/EBWebView/Default/Cache/Cache_Data/data_1
```

Extract string di file itu:

```bash
strings -a recovered_user/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/LocalState/EBWebView/Default/Cache/Cache_Data/data_1 | grep github_pat_
```

Keluar token PAT GitHub utuh. Token itu ternyata pernah diketik ke Bing search, jadi kesimpan di cache request URL.

Validasi token ke GitHub API:

```bash
TOKEN='github_pat_...redacted...'
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user
```

Lanjut list repo private milik akun itu:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  'https://api.github.com/user/repos?visibility=all&affiliation=owner,collaborator,organization_member&per_page=100'
```

Ada repo private `idiot-communication`, dan field `description` langsung berisi flag:

```text
"description": "sctf{0n1y_4n_idi0t_1s_th1s_uns3cur3}"
```

Flag:

```text
sctf{0n1y_4n_idi0t_1s_th1s_uns3cur3}
```
