# C++ Unplugged

- **CTF:** BroncoCTF
- **Category:** Reverse
- **Difficulty:** Medium
- **Flag:** `bronco{i_c@m3_1n_lik3_@_s3gfAult}`

## Temuan Awal

File terlihat seperti C++ yang seluruh keyword dan operatornya diganti judul lagu:

```cpp
using namespace std EndGame

void updateNum FromTheStart CountingStars Starboy start IsItOverNow BeginAgain
```

Hint menyebut semua judul yang harus diganti dimulai dengan huruf kapital. Token biasa seperti nama fungsi dan variabel tetap dipertahankan.

Potongan di atas menjadi:

```cpp
using namespace std;

void updateNum(int *start) {
```

## Mapping Token

Mapping utama bisa ditentukan dari posisi sintaksnya:

| Judul lagu | Token C++ |
|---|---|
| `EndGame` | `;` |
| `FromTheStart` | `(` |
| `IsItOverNow` | `)` |
| `BeginAgain` | `{` |
| `EndOfTime` | `}` |
| `CountingStars` | `int` |
| `CallItWhatYouWant` | `string` |
| `Abcdefu` | `char` |
| `BadIdeaRight` | `bool` |
| `TruthHurts` | `true` |
| `FalseGod` | `false` |
| `ThisIsMe` | `=` |
| `SameOldLove` | `==` |
| `SmallerThanThis` | `<` |
| `Higher` | `>` |
| `Greedy` | `&&` |
| `ThisOrThat` | `||` |
| `WithoutMe` | `-` |
| `Starboy` | `*` |
| `BreakUpWithYourGirlfriendImBored` | `/` |
| `PartOfMe` | `%` |
| `Mine` | `+=` |
| `More` | `++` |
| `PleasePleasePlease` | `if` |
| `ShouldveSaidNo` | `else` |
| `DejaVu` | `while` |
| `GoodForYou` | `for` |
| `Positions` | `switch` |
| `CaseClosed` | `case` |
| `AsItWas` | `default` |
| `YouBrokeMeFirst` | `break` |
| `OnMyWay` | `continue` |
| `ComeBackBeHere` | `return` |
| `PieceByPiece` | `[` |
| `FreshOutTheSlammer` | `]` |

Beberapa judul sengaja ditempel:

```text
counterMore                    -> counter++
flag_selector_1WithoutMeWithoutMe -> flag_selector_1--
SmallerThanThisThisIsMe        -> <=
HigherThisIsMe                 -> >=
Abcdefuacters                  -> characters
```

Dua `BreakUpWithYourGirlfriendImBored` yang berdempetan menghasilkan `//`, sehingga teks setelahnya menjadi komentar.

Tiga placeholder di array karakter ditulis dengan spasi:

```cpp
' Starboy ', ' BeginAgain ', ' EndOfTime '
```

Hasil yang dimaksud adalah:

```cpp
'*', '{', '}'
```

## Output `part1()`

Kondisi awal:

```cpp
var1 && var2 > var3
true && 22 > 13
```

bernilai benar. Selector mulai dari `-4`, ditambah `7`, lalu dikurangi satu:

```text
-4 + 7 - 1 = 2
```

`switch` masuk ke `case 2`.

`updateNum(&var5)` mengubah `var5` dari `1` menjadi `7`, sehingga:

```cpp
something = "bron";
```

Output:

```text
bron
```

## Output `part2()`

Array karakter:

```cpp
{'b','#','c','i','u','&','e','@','d','o','p','t','*','3','{','}'}
```

Pemilihan indeks:

```text
5 % 3 = 2      -> c
characters[9]  -> o
characters[14] -> {
```

Output:

```text
co{
```

## Output `part3()`

Loop `switch` menghasilkan:

```text
i = 0 -> smallerParts[8]  -> i
i = 1 -> smallerParts[38] -> _
i = 2 -> smallerParts[2]  -> c
i = 3 -> smallerParts[36] -> @
i = 4 -> smallerParts[12] -> m
default -> smallerParts[29] -> 3
```

Output:

```text
i_c@m3
```

## Output `part4()`

Loop berjalan dari `i = 21` dan berhenti setelah `i` menjadi `31`.

Karakter yang ditambahkan berturut-turut:

```text
i=21 -> _
i=22 -> 1
i=23 -> n
i=25 -> _
i=26 -> l
i=27 -> i
i=29 -> k
i=30 -> 3
```

Nilai `24` dan `28` dilewati oleh cabang `continue`.

Output:

```text
_1n_lik3
```

## Output `part5()`

Untuk `i = 0, 1, 2`, kondisi pertama selalu salah. Fungsi `secretMath()` mengembalikan:

```text
secretMath(0) = 100 - 5 = 95  -> _
secretMath(1) = 32 * 2  = 64  -> @
secretMath(2) = 19 * 5  = 95  -> _
```

Output:

```text
_@_
```

## Output `part6()`

Ekspresi karakter menghasilkan:

```text
char(100 + 15)       -> s
char(50 + 1)         -> 3
char(110 - 7)        -> g
char(102 * 1)        -> f
char(60 + 12 % 7)    -> A
char(130 - 13)       -> u
char(54 * 2)         -> l
char(122 - 6)        -> t
char(25 * 5)         -> }
```

Output:

```text
s3gfAult}
```

## Hasil Akhir

`main()` menggabungkan seluruh fungsi:

```text
bron
+ co{
+ i_c@m3
+ _1n_lik3
+ _@_
+ s3gfAult}
```

Hasil program:

```text
The flag is bronco{i_c@m3_1n_lik3_@_s3gfAult}
```

Kalimatnya merupakan parodi lirik:

```text
I came in like a segfault
```

## Solver

`solve.py` mengganti seluruh judul lagu dengan token C++, mengompilasi source hasil restorasi, menjalankannya, lalu mengambil flag dari output.

```bash
python3 solve.py totallynormalcode.cpp
```

Solver juga bisa membaca file hasil copy-paste terminal selama bagian source masih memuat `#include`.

Output:

```text
The flag is bronco{i_c@m3_1n_lik3_@_s3gfAult}
[+] Flag: bronco{i_c@m3_1n_lik3_@_s3gfAult}
```

## Flag

```text
bronco{i_c@m3_1n_lik3_@_s3gfAult}
```
