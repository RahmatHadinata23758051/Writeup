Iya, kalau untuk **langsung disimpan sebagai file `.md`**, jangan pakai nested code fence di dalamnya karena itu yang bikin tampilan terlihat terpisah. Berikut isi `.md` mentahnya. Tinggal copy **semuanya** mulai dari `# scriptCTF...` sampai akhir ke file `writeup.md`.

```markdown
# scriptCTF 2026 — OSINT Writeup

## The New One 2

### Challenge

> **The New One 2**
>
> This New One has a very unique wishlist! Can you find what its hiding?
>
> Wrap the flag in `scriptCTF{}`

### Goal

Melanjutkan hasil dari **The New One 1**, lalu mencari pesan tersembunyi pada wishlist milik member baru.

---

## 1. Pivot from The New One 1

Pada challenge sebelumnya, member baru yang ditemukan adalah:

    john.hacker.doe1337

Di Discord, profil tersebut menggunakan display name:

    Troller

Username:

    john.hacker.doe1337

Pada profil Discord terdapat tab:

    Activity | Wishlist | No Mutual Friends | 1 Mutual Server

Karena challenge secara eksplisit menyebut **wishlist**, tab tersebut menjadi pivot utama untuk challenge ini.

---

## 2. Inspecting the Wishlist

Wishlist berisi 13 item Discord Collectibles.

Dengan membuka **DevTools → Network** ketika membuka tab Wishlist, response API dapat dilihat dan nama item dapat diekstrak.

Urutan item dari response API:

    1. The Hermit
    2. South Korea
    3. Enchanted Forest
    4. Brazil
    5. Ecuador
    6. He-Bat
    7. The Tower
    8. Oni Mask
    9. France
    10. Haiti
    11. Saudi Arabia
    12. Iraq
    13. Woody

Wishlist Discord ditampilkan dengan item terbaru terlebih dahulu. Karena itu, urutan item perlu dibalik terlebih dahulu untuk mendapatkan pesan yang ditanam oleh pembuat challenge.

---

## 3. Reverse the Order

Setelah dibalik:

    Woody
    Iraq
    Saudi Arabia
    Haiti
    France
    Oni Mask
    The Tower
    He-Bat
    Ecuador
    Brazil
    Enchanted Forest
    South Korea
    The Hermit

Kemudian ambil huruf pertama dari setiap item:

    W  Woody
    I  Iraq
    S  Saudi Arabia
    H  Haiti
    F  France
    O  Oni Mask
    T  The Tower
    H  He-Bat
    E  Ecuador
    B  Brazil
    E  Enchanted Forest
    S  South Korea
    T  The Hermit

Hasilnya:

    WISHFOTHEBEST

Perhatikan bahwa hasil literalnya adalah:

    WISHFOTHEBEST

bukan:

    WISHFORTHEBEST

Jadi tidak perlu menambahkan huruf `R`.

---

## 4. Flag

Challenge meminta hasil tersebut dibungkus menggunakan format:

    scriptCTF{}

Sehingga flag akhirnya:

    scriptCTF{WISHFOTHEBEST}

---

## 5. Intended Path

    The New One 1
           ↓
    john.hacker.doe1337
           ↓
    Discord profile
           ↓
    Wishlist
           ↓
    Extract item names
           ↓
    Reverse order
           ↓
    Take first letter of each item
           ↓
    WISHFOTHEBEST
           ↓
    scriptCTF{WISHFOTHEBEST}

---

## Flag

    scriptCTF{WISHFOTHEBEST}
```

