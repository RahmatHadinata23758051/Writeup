# CTF Writeup — Concealed Surveilance

**Event:** JerseyCTF  
**Category:** Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{th3_commod0r3str@ted_!nt0_h@ve_inf1l_th3_apoll0!}`

---

## Challenge Description

> Recently, rumors have arisen that Tony Wonder had access to Cold War secrets regarding confidential governmental contracts with IBM. They have been targeting Tony for some time, and it's our job to identify the espionage. Given this logical file containing parts of his system, can you?
>
> Identify more information about the secondary user on the machine.
>
> Identify the mediums of persistence that Soviets agents have.
> there is four information fragments that need to be identified!
>
> hint: A description of who the secondary user would be a good start

**Artifact:** logical Windows filesystem dump (`Users/`, `ProgramData/`, `Windows/`)

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
ls -la
rg --files
```

Temuan awal:
- Secondary profile: `Users/commodore64`
- Script mencurigakan:
  - `Users/Tony Wonder/Documents/test.ps1`
  - `ProgramData/telemetry.ps1`
- Scheduled task anomali:
  - `Windows/System32/Tasks/Windows Update`

### Step 2 — Inspect Suspicious Scripts

```bash
sed -n '1,220p' ProgramData/telemetry.ps1
sed -n '1,220p' Users/Tony\ Wonder/Documents/test.ps1
```

`test.ps1` membuat akun `commodore64` sebagai Administrator dan menyimpan base64 di field Description.

`telemetry.ps1` melakukan beacon ke:
- `http://telemetry.apollo-xiiv.local/dHJAdGVkXyFudDA=/$c/$u/$t`

---

## Exploitation

### Step 3 — Fragment #1 (Secondary User Description)

Dari `test.ps1`:
```powershell
New-LocalUser ... -Description "amN0Znt0aDNfY29tbW9kMHIzcw"
```

Decode:
```bash
echo 'amN0Znt0aDNfY29tbW9kMHIzcw' | base64 -d
# → jctf{th3_commod0r3s
```

### Step 4 — Fragment #2 (Telemetry Token)

Dari `telemetry.ps1`:
```powershell
.../dHJAdGVkXyFudDA=/$c/$u/$t
```

Decode:
```bash
echo 'dHJAdGVkXyFudDA=' | base64 -d
# → tr@ted_!nt0
```

### Step 5 — Persistence Medium #1: Malicious Scheduled Task

Analisis task:
```bash
iconv -f UTF-16LE -t UTF-8 'Windows/System32/Tasks/Windows Update'
```

Temuan:
- `Author`: `APOLLO-XIIV\commodore64`
- Hidden scheduled task
- Trigger: `BootTrigger`
- Action:
  ```xml
  <Command>powershell.exe</Command>
  <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\script.ps1</Arguments>
  ```

Task Description berisi fragment:
- `X2hAdmVfaW5mMWw`

Decode:
```bash
echo 'X2hAdmVfaW5mMWw' | base64 -d
# → _h@ve_inf1l
```

### Step 6 — Persistence Medium #2: WMI Permanent Event Subscription

Dari command history:
```bash
sed -n '1,240p' Users/commodore64/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
```

Terlihat pembuatan:
- `__EventFilter` (`WindowsTelemetryFilter`)
- `CommandLineEventConsumer` (`WindowsTelemetryConsumer`)
- `__FilterToConsumerBinding`

Consumer menjalankan:
```powershell
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\telemetry.ps1
```

Juga ditemukan base64 fragment:
- `X3RoM19hcG9sbDAhfQ==`

Decode:
```bash
echo 'X3RoM19hcG9sbDAhfQ==' | base64 -d
# → _th3_apoll0!}
```

---

## Flag

```
jctf{th3_commod0r3str@ted_!nt0_h@ve_inf1l_th3_apoll0!}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | Local Account Persistence | Akun `commodore64` dibuat sebagai Administrator, `AccountNeverExpires` |
| 2 | Scheduled Task Persistence | Task palsu `\Windows Update`, hidden + boot trigger + PowerShell payload |
| 3 | WMI Persistence | `__EventFilter` + `CommandLineEventConsumer` + `__FilterToConsumerBinding` |
| 4 | Obfuscation | 4 fragmen flag disimpan dalam base64 di artefak berbeda |

---

## Tools Used

- `rg` / `sed` / `strings`
- `regripper`
- `iconv`
- `base64`
- Python (`solve.py`)

---

## Attack Flow

```
Logical File Dump
      │
      ▼
Find suspicious artifacts (test.ps1, telemetry.ps1, Windows Update task)
      │
      ▼
Decode base64 fragments from:
- user description
- telemetry URI token
- task description
- PSReadLine (WMI setup)
      │
      ▼
Correlate persistence mediums:
- Scheduled Task
- WMI subscription
      │
      ▼
jctf{th3_commod0r3str@ted_!nt0_h@ve_inf1l_th3_apoll0!}
```

---

## Installation

```bash
# Run solver
python3 solve.py
```
