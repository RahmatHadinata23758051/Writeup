Iya, maksudnya kamu ingin **seluruh isi benar-benar berada dalam satu blok `.md`**, bukan ada bagian yang ter-render/terpisah. Copy yang ini:

````markdown
# scriptCTF 2026 — OSINT Writeup

## The New One 1

### Challenge

> **The New One 1**
>
> `"Can I join your team?" - Armored Pawn`
>
> `"Nah, we don't need more members" - NoobMaster`
>
> *Proceeds to let a new member join that is not Armored Pawn*
>
> **Note:** Please do not OSINT Armored Pawn, he is not related to the challenge, just a troll in our server :)

### Goal

Mencari anggota baru yang dimaksud oleh challenge dan menemukan flag yang disembunyikan pada jejak publiknya.

---

## 1. Recon

Clue paling penting dari challenge:

- `NoobMaster`
- Ada sebuah **team**
- Ada **new member**
- Armored Pawn secara eksplisit disebut **bukan target**

Daripada melakukan OSINT terhadap Armored Pawn, pencarian diarahkan ke tim yang berkaitan dengan `NoobMaster`, yaitu **ScriptSorcerers**.

Website tim:

```text
https://scriptsorcerers.xyz/
```

Pada bagian member ditemukan profil baru:

```text
https://scriptsorcerers.xyz/members/john.hacker.doe1337
```

Username member tersebut:

```text
john.hacker.doe1337
```

---

## 2. Finding the Flag

Saat profil `john.hacker.doe1337` dibuka, halaman tersebut menampilkan:

```text
# Newbie

Hey! I am the new guy! I know I wish Armored Pawn was here....
anyways here's a flag:
scriptCTF{17s_0bv10usly_0S1NT_71m3}
```

Dari sini flag dapat langsung diambil.

Konten profil juga dapat ditemukan di JavaScript chunk hasil build Vite:

```bash
curl -sL \
'https://scriptsorcerers.xyz/assets/john.hacker.doe1337-CiZOvxQ1.js'
```

Isi chunk:

```javascript
const e=`# Newbie
Hey! I am the new guy! I know I wish Armored Pawn was here....
anyways here's a flag: scriptCTF{17s_0bv10usly_0S1NT_71m3}
`;export{e as default};
```

Hal ini mengonfirmasi bahwa flag memang merupakan bagian dari konten profil member baru.

---

## 3. Flag

```text
scriptCTF{17s_0bv10usly_0S1NT_71m3}
```
````
