# CTF Writeup — You gotta run, run, run, run, run

**Event:** CTF@CIT 2026  
**Category:** Forensics / Windows Persistence  
**Difficulty:** Medium  
**Flag:** `CIT{AzureTenant}`

---

## Challenge Description

> Waiter, waiter! More persistence mechanisms please!!
>
> Yet another persistence mechanism seems to have been setup. It's funny because I remember the user saying everytime they logged into their system, something just felt odd when they'd see some sort of black box flash on their screen. There must be a name associated with what this is..

**File:** `challenge.dat`

---

## Reconnaissance

### Step 1 — Identify artifact type

```bash
file challenge.dat
```

Output menunjukkan ini adalah **Windows Registry hive** (`NTUSER.DAT` type), jadi fokus analisis diarahkan ke key persistence user-level.

### Step 2 — Parse common autorun keys

```bash
regripper -r challenge.dat -p run
```

Temuan penting:

- Key: `Software\Microsoft\Windows\CurrentVersion\Run`
- Value mencurigakan:
  - `AzureTenant - "C:\Users\kurt\AppData\Roaming\fj3493.exe"`

Nama value inilah yang diminta challenge.

---

## Analysis Notes

Gejala "black box flash saat login" sangat konsisten dengan payload yang dijalankan dari key `Run` (sering memunculkan jendela `cmd`/proses singkat di startup user session).

Dengan demikian, nama persistence yang dimaksud adalah:

- `AzureTenant`

---

## Flag

```text
CIT{AzureTenant}
```

---

## Solver

File solver disimpan sebagai `solve.py` di folder yang sama.

Jalankan:

```bash
python3 solve.py
```

Atau dengan path custom:

```bash
python3 solve.py /path/to/challenge.dat
```
