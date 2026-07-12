# Prompt And Pretext

File yang paling relevan ada di `Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx`. Nama filenya sudah ngasih arah: PowerShell Script Block Logging event `4104`, jadi targetnya cari script yang jalan dan lihat apakah ada phishing prompt.

Recon singkat:

```bash
rtk file 'Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx'
rtk strings -n 8 'Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx' | head
```

`file` mengonfirmasi ini memang Windows EVTX. `strings` tidak terlalu membantu karena isi event tersimpan dalam format biner log.

Langkah berikutnya pakai parser EVTX dan dump XML record pertama:

```bash
source /home/nata/ctf_env/bin/activate
python - <<'PY'
from Evtx.Evtx import Evtx
with Evtx("Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx") as log:
    for i, rec in enumerate(log.records()):
        print(f"--- RECORD {i} ---")
        print(rec.xml())
        if i >= 1:
            break
PY
```

Record `0` berisi stage-1 obfuscated:

```powershell
&([scriptblock]::create((New-Object System.IO.StreamReader(
  New-Object System.IO.Compression.GzipStream(
    (New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('...'))),
    [System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))
```

Itu pola klasik `base64 -> gzip -> execute`. Saya decode payload-nya:

```bash
python - <<'PY'
import base64, gzip, re
from Evtx.Evtx import Evtx
with Evtx("Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx") as log:
    xml0 = next(log.records()).xml()
m = re.search(r"FromBase64String\\('([^']+)'\\)", xml0)
print(gzip.decompress(base64.b64decode(m.group(1))).decode())
PY
```

Hasil deobfuscation:

```powershell
function Invoke-LoginPrompt{
...
R{START_PROCESS}
}
Invoke-LoginPrompt
```

Bagian pentingnya:

- Fungsi yang meminta kredensial: `Invoke-LoginPrompt`
- Placeholder marker untuk aksi berikutnya: `R{START_PROCESS}`, jadi komponen marker yang dipakai adalah `RSTART_PROCESS`

Flag akhir:

```text
grodno{Invoke-LoginPrompt_RSTART_PROCESS}
```
