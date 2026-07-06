# Customer Service Writeup

Challenge ini kelihatannya seperti checker theorem prover sederhana: kita kirim JSON dalam bentuk hex, server mem-parse item theory, lalu kalau bisa membuat theorem `false` tanpa asumsi maka flag keluar.

Setelah baca `checker.py`, ada dua bug penting.

Yang pertama ada di alur item `thm`. Server memang memanggil `monitor.check_proof(item, rewrite=False)` dan memastikan status-nya `OK` atau `ProofOK`. Tapi sesudah itu theorem yang sama dimasukkan ke theory lewat:

```python
exts = item.get_extension()
report = theory.thy.checked_extend(exts)
```

Masalahnya, `items.Theorem.get_extension()` tidak pernah membawa proof yang barusan diverifikasi. Extension yang dihasilkan tetap:

```python
extension.Theorem(self.name, Thm(self.prop))
```

Artinya theorem tersebut ditambahkan sebagai **axiom**, bukan theorem terverifikasi.

Bug kedua ada di filter axiom:

```python
if (len(report.get_axioms())) > 1:
    ...
elif report.get_axioms() == 1 and item.ty != "thm":
    ...
```

Cabang kedua salah karena `report.get_axioms()` mengembalikan list, bukan integer. Jadi item `thm` yang diam-diam menambah satu axiom tidak pernah ditolak.

Dari situ exploit-nya sederhana:

1. Kirim item bertipe `thm`.
2. Isi `prop` dengan `false` supaya theorem yang tersimpan jadi `|- false`.
3. Isi `proof` dengan proof lain yang valid, walaupun tidak membuktikan `false`.

Kenapa bisa? Karena `monitor.check_proof()` untuk mode `proof` hanya memeriksa proof yang dikirim valid secara internal. Dia tidak mencocokkan hasil proof itu dengan `item.prop`. Jadi proof `|- false = false` juga lolos.

Payload final yang dipakai:

```json
{
  "content": [
    {
      "ty": "thm",
      "name": "pwn",
      "vars": {"false": "bool"},
      "prop": "false",
      "proof": [
        {
          "id": "0",
          "rule": "reflexive",
          "args": "false",
          "prevs": [],
          "th": ""
        }
      ]
    }
  ]
}
```

Proof di atas sah karena rule `reflexive` menghasilkan `|- false = false` untuk variabel bernama `false` bertipe `bool`. Checker lalu berkata “proof check passed”, tetapi saat theorem dimasukkan ke theory, yang disimpan justru `|- false` sebagai axiom. Fungsi:

```python
theorem_proves_false_unconditioned(thm)
```

langsung mendeteksi theorem itu sebagai kontradiksi tanpa asumsi, lalu memanggil `win()`.

Flag yang keluar:

```text
GPNCTF{Ex-uN4-LInea-v4cua-sequ1tUr-QUOdL18e7}
```
