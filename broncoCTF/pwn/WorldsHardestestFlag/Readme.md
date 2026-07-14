# World's Hardestest Flag

**Category:** Misc / Roblox  
**Challenge:** World's Hardestest Flag  
**Flag:** `bronco{d34th_t0_th3_dehs_f0r3v3r}`

## Challenge Description

> This is Mr. Deh speaking.
>
> I've had enough.
>
> This.
>
> Is.
>
> My.
>
> Final.
>
> Stand.
>
> No more client-sided freebies.
>
> No more funny business. Your commands get executed on my special SecureDeh9001Server. You still have freedom (questionable), but I stay safe.
>
> In fact, I'm even building my own server on top of the original game using the Roblox Engine.
>
> (Wait, what?)
>
> Also, there's a flag on my super awesome server, but you'll have to beat the game to get it.

File yang diberikan:

```text
mrdeh-hardestest.rbxl
```

## Overview

Challenge ini berupa game Roblox dengan obstacle course yang dipenuhi musuh bernama **Dehnemy**. Secara normal, pemain harus menyelesaikan seluruh level sampai menyentuh objek `WinPad`.

Namun, di dalam game terdapat terminal bernama **Secure Deh-9001 Terminal**. Terminal tersebut menerima kode Lua dari pemain dan mengirimkannya ke server untuk dieksekusi.

Developer mencoba mengamankan terminal menggunakan blacklist kata tertentu. Masalahnya, blacklist hanya memeriksa substring pada source code mentah. Operasi yang sama masih dapat dilakukan menggunakan API Roblox lain yang tidak diblokir.

Alih-alih menyelesaikan seluruh obstacle course, objek kemenangan dapat dicari lalu dipindahkan langsung ke karakter pemain.

## Initial Analysis

Pemeriksaan awal terhadap file:

```bash
file mrdeh-hardestest.rbxl
strings -a mrdeh-hardestest.rbxl | \
    grep -iE 'terminal|winpad|execute|flag|dehnemy|winner'
```

Beberapa nama penting yang ditemukan:

```text
SecureDeh9001TerminalScript
SecureDeh9001Server-Pipeline
ExecuteCode
WIN
WinnerPopup
WinPad
```

Temuan tersebut menunjukkan bahwa:

1. Terminal memiliki script client.
2. Input terminal dikirim melalui sebuah `RemoteEvent`.
3. Terdapat remote function bernama `WIN`.
4. Kondisi kemenangan berkaitan dengan objek bernama `WinPad`.
5. Flag ditampilkan melalui GUI `WinnerPopup`.

## Terminal Logic

Script terminal mengambil isi textbox dan melakukan pengecekan blacklist sebelum mengirim kode ke server.

Daftar kata yang diblokir:

```lua
local bannedWords = {
    "position",
    "humanoid",
    "destroy",
    "name",
    "typetag",
    "flag"
}
```

Pengecekannya hanya menggunakan pencarian substring:

```lua
local function containsBannedWords(input)
    for _, word in bannedWords do
        if string.find(string.lower(input), word) then
            return true
        end
    end

    return false
end
```

Apabila salah satu kata terlarang ditemukan, karakter pemain dibunuh:

```lua
if containsBannedWords(code) then
    killPlayer()
    errorLog.Text = "AHA! GOT YOU!!!"
    return
end
```

Jika tidak ditemukan, input dikirim ke server:

```lua
executeEvent:FireServer(code)
```

Jadi, perlindungannya bukan sandbox Lua sungguhan. Server tetap mengeksekusi kode pemain, sementara filter hanya melarang beberapa string.

## Win Condition

Pada script pengendali karakter ditemukan kondisi kemenangan berikut:

```lua
elseif not (string.match(obj.Name, "WinPad") == nil) then
    local winGui = LocalPlayer.PlayerGui:FindFirstChild("Win")
    winGui.Enabled = true

    local flag = winFunc:InvokeServer()
    winGui.WinnerPopup.Flag.Text = "" .. flag
end
```

Alurnya:

1. Karakter menyentuh objek yang namanya mengandung `WinPad`.
2. GUI kemenangan diaktifkan.
3. Client memanggil `WIN:InvokeServer()`.
4. Server mengembalikan flag.
5. Flag ditampilkan pada `WinnerPopup`.

Flag tidak disimpan langsung pada client. Karena itu, membuat GUI palsu atau mengubah teks popup tidak cukup. Objek `WinPad` yang asli harus disentuh agar remote kemenangan dipanggil.

## Blacklist Bypass

Payload biasa seperti berikut tidak dapat digunakan:

```lua
print(v.Name)
```

Kata `name` termasuk blacklist.

Mengubah posisi seperti ini juga diblokir:

```lua
v.Position = ...
```

Kata `position` juga termasuk blacklist.

Akan tetapi, nama sebuah Roblox `Instance` dapat diperoleh melalui:

```lua
tostring(v)
```

Sedangkan lokasi objek dapat diubah menggunakan properti:

```lua
v.CFrame
```

Kedua cara tersebut tidak mengandung kata yang diblokir.

Untuk mencari objek kemenangan, semua descendant di dalam `workspace` dapat diperiksa:

```lua
for _,v in ipairs(workspace:GetDescendants()) do
    if tostring(v):find("WinPad") then
        print(v)
    end
end
```

Payload tersebut tidak menggunakan:

```text
position
humanoid
destroy
name
typetag
flag
```

## Exploitation

Karena server challenge berjalan sebagai single-player, pemain lokal dapat diambil sebagai elemen pertama dari `GetPlayers()`:

```lua
local p = game:GetService("Players"):GetPlayers()[1]
```

Setelah itu, cari `WinPad` asli dan pindahkan ke pivot karakter:

```lua
local p=game:GetService("Players"):GetPlayers()[1]

for _,v in ipairs(workspace:GetDescendants()) do
    if tostring(v):find("WinPad") and v:IsA("BasePart") then
        v.CFrame=p.Character:GetPivot()
        break
    end
end
```

Payload final dalam satu baris:

```lua
local p=game:GetService("Players"):GetPlayers()[1] for _,v in ipairs(workspace:GetDescendants()) do if tostring(v):find("WinPad") and v:IsA("BasePart") then v.CFrame=p.Character:GetPivot() break end end
```

Payload tetap lolos dari blacklist karena tidak mengandung kata terlarang.

## Exploit Flow

Ketika payload dijalankan:

```text
Terminal
   │
   ├── melakukan pengecekan blacklist
   │
   └── ExecuteCode:FireServer(payload)
                │
                ▼
       SecureDeh9001Server
                │
                ├── mengeksekusi kode Lua
                ├── mencari WinPad
                └── memindahkan WinPad ke karakter
                              │
                              ▼
                     Karakter menyentuh WinPad
                              │
                              ▼
                     WIN:InvokeServer()
                              │
                              ▼
                       Flag ditampilkan
```

Dengan memindahkan `WinPad`, seluruh obstacle course dapat dilewati.

## Flag

```text
bronco{d34th_t0_th3_dehs_f0r3v3r}
```
