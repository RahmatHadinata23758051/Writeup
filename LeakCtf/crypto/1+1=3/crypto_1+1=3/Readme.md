# Writeup CTF: 1+1=3

## Deskripsi Challenge

Challenge ini merupakan soal crypto berbasis Zero Knowledge Proof menggunakan Groth16 dari library `gnark`.

Judul challenge:

```text
1+1=3
```

Deskripsi:

```text
ZK is just finding Δ Λ Γ
```

Service menyediakan dua endpoint utama:

```text
/challenge
/submit
```

Endpoint `/challenge` memberikan `seed` dan public input berupa tiga nilai:

```text
[x, y, z]
```

Namun nilai `z` dibuat dengan rumus:

```text
z = x + y + 1
```

Padahal circuit yang digunakan pada source challenge melakukan pengecekan:

```go
api.AssertIsEqual(api.Add(c.X, c.Y), c.Z)
```

Artinya circuit mengharuskan:

```text
x + y = z
```

Karena server memberikan `z = x + y + 1`, public input yang diberikan sebenarnya tidak valid. Tujuan challenge adalah mengirim proof yang tetap lolos verifikasi untuk statement palsu tersebut.

Flag yang diperoleh:

```text
L3AK{1_Plus_1_EquAls_3_gaMMa4637_Linear663_delTA6926_113377}
```

## Analisis Awal

Ketika mencoba membuat proof normal menggunakan proving key yang diberikan, proof tidak lolos verifikasi lokal. Hal ini menunjukkan bahwa pendekatan biasa, yaitu membuat witness valid lalu melakukan `groth16.Prove`, tidak cukup.

Beberapa percobaan awal seperti mencari relasi kecil antara `gamma` dan `delta`, discrete log kecil, atau membuat proof valid untuk `z - 1` juga gagal. Dari sini terlihat bahwa kelemahan challenge bukan berada pada witness biasa, tetapi pada cara verifier gnark menangani proof tambahan, khususnya bagian commitment.

## Bug Utama

Pada versi gnark yang digunakan challenge, verifier menambahkan semua `proof.Commitments` ke nilai public input commitment atau `kSum`.

Secara sederhana, verifier menghitung public input commitment seperti ini:

```text
kSum = K0 + x*K1 + y*K2 + z*K3
```

Lalu verifier juga menambahkan commitment dari proof:

```text
kSum = kSum + commitment_0 + commitment_1 + ...
```

Masalahnya, circuit pada challenge ini sebenarnya tidak memiliki committed variable. Namun verifier tetap menerima array `proof.Commitments` dari proof yang kita kirim.

Selain itu, proof of knowledge untuk commitment tidak mengecek jumlah commitment mentah satu per satu. Yang dicek adalah folded commitment hasil Fiat Shamir challenge.

Jadi kita bisa membuat dua fake commitment `C0` dan `C1` dengan kondisi:

```text
C0 + C1 = -kSum
```

agar nilai efektif `kSum` menjadi nol:

```text
kSum + C0 + C1 = 0
```

Tetapi folded commitment dibuat nol juga:

```text
C0 + r*C1 = 0
```

Dengan begitu, proof of knowledge commitment dapat dibuat sebagai point nol.

## Ide Exploit

Karena kita bisa mengontrol `proof.Commitments`, kita tidak perlu membuat proof valid menggunakan proving key. Kita cukup membuat proof palsu langsung dari verifying key.

Kita set:

```text
Ar  = vk.G1.Alpha
Bs  = vk.G2.Beta
Krs = 0
```

Lalu kita buat commitments supaya:

```text
commitments_sum = -kSum(public)
```

Maka pairing equation menjadi valid karena bagian public input berhasil dinetralkan.

Untuk membuat folded commitment bernilai nol, kita ambil challenge `r` dari Fiat Shamir transcript. Karena circuit tidak memiliki commitment asli, seed commitment serialized-nya kosong.

Kita ingin:

```text
C0 + C1 = D
C0 + r*C1 = 0
```

dengan:

```text
D = -kSum
```

Dari dua persamaan tersebut:

```text
C1 = D / (1 - r)
C0 = -r * D / (1 - r)
```

Setelah itu proof dikirim ke `/submit`.

## Solver

```go
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend/groth16"
	g16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

const BASE = "https://one-plus-one-equals-three.instances.ctf.l3ak.team"

var FrMod, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617",
	10,
)

type AddCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
}

func (c *AddCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(c.X, c.Y), c.Z)
	return nil
}

type ChallengeResponse struct {
	Seed   string   `json:"seed"`
	Public []string `json:"public"`
}

func numberFromSeed(label string, seed string) uint64 {
	h := sha256.Sum256([]byte(label + ":" + seed))
	n := binary.BigEndian.Uint64(h[:8])
	return n%1_000_000 + 1
}

func circuitInputFromSeed(seed string) (*big.Int, *big.Int, *big.Int) {
	x := numberFromSeed("x", seed)
	y := numberFromSeed("y", seed)
	z := x + y + 1

	return new(big.Int).SetUint64(x),
		new(big.Int).SetUint64(y),
		new(big.Int).SetUint64(z)
}

func loadVK() (groth16.VerifyingKey, *g16.VerifyingKey) {
	vkHex, err := os.ReadFile("vk.hex")
	if err != nil {
		panic(err)
	}

	vkBytes, err := hex.DecodeString(string(bytes.TrimSpace(vkHex)))
	if err != nil {
		panic(err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		panic(err)
	}

	vkBn, ok := vk.(*g16.VerifyingKey)
	if !ok {
		panic("vk type assertion failed")
	}

	return vk, vkBn
}

func getChallenge() ChallengeResponse {
	resp, err := http.Get(BASE + "/challenge")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var ch ChallengeResponse
	if err := json.Unmarshal(data, &ch); err != nil {
		fmt.Println(string(data))
		panic(err)
	}

	return ch
}

func makePublicWitness(x, y, z *big.Int) witness.Witness {
	w := AddCircuit{
		X: x,
		Y: y,
		Z: z,
	}

	pw, err := frontend.NewWitness(
		&w,
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		panic(err)
	}

	return pw
}

func addG1(a, b *curve.G1Affine) curve.G1Affine {
	var acc curve.G1Jac
	acc.FromAffine(a)
	acc.AddMixed(b)

	var out curve.G1Affine
	out.FromJacobian(&acc)
	return out
}

func negG1(p *curve.G1Affine) curve.G1Affine {
	var out curve.G1Affine
	out.Neg(p)
	return out
}

func mulG1(p *curve.G1Affine, s *big.Int) curve.G1Affine {
	var out curve.G1Affine
	out.ScalarMultiplication(p, s)
	return out
}

func ksum(vkBn *g16.VerifyingKey, x, y, z *big.Int) curve.G1Affine {
	scalars := []*big.Int{x, y, z}

	var acc curve.G1Jac
	acc.FromAffine(&vkBn.G1.K[0])

	for i, s := range scalars {
		var tmp curve.G1Affine
		tmp.ScalarMultiplication(&vkBn.G1.K[i+1], s)
		acc.AddMixed(&tmp)
	}

	var out curve.G1Affine
	out.FromJacobian(&acc)
	return out
}

func foldChallengeEmptySeed() *big.Int {
	t := fiatshamir.NewTranscript(sha256.New(), "r")

	if err := t.Bind("r", []byte{}); err != nil {
		panic(err)
	}

	rBytes, err := t.ComputeChallenge("r")
	if err != nil {
		panic(err)
	}

	var r fr.Element
	r.SetBytes(rBytes)

	var rBig big.Int
	r.BigInt(&rBig)

	return &rBig
}

func fakeCommitmentsWithSum(D curve.G1Affine) []curve.G1Affine {
	r := foldChallengeEmptySeed()
	fmt.Println("[+] fold challenge r:", r.String())

	oneMinusR := new(big.Int).Sub(big.NewInt(1), r)
	oneMinusR.Mod(oneMinusR, FrMod)

	inv := new(big.Int).ModInverse(oneMinusR, FrMod)
	if inv == nil {
		panic("1-r not invertible")
	}

	c1Scalar := new(big.Int).Set(inv)

	c0Scalar := new(big.Int).Neg(r)
	c0Scalar.Mul(c0Scalar, inv)
	c0Scalar.Mod(c0Scalar, FrMod)

	C0 := mulG1(&D, c0Scalar)
	C1 := mulG1(&D, c1Scalar)

	return []curve.G1Affine{C0, C1}
}

func proofToHex(proof *g16.Proof) string {
	var buf bytes.Buffer

	if _, err := proof.WriteTo(&buf); err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf.Bytes())
}

func submit(seed string, proofHex string) string {
	body := map[string]string{
		"seed":      seed,
		"proof_hex": proofHex,
	}

	raw, _ := json.Marshal(body)

	resp, err := http.Post(BASE+"/submit", "application/json", bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return string(data)
}

func main() {
	vk, vkBn := loadVK()

	ch := getChallenge()
	fmt.Println("[+] seed:", ch.Seed)
	fmt.Println("[+] public:", ch.Public)

	x, y, z := circuitInputFromSeed(ch.Seed)

	fmt.Println("[+] x:", x.String())
	fmt.Println("[+] y:", y.String())
	fmt.Println("[+] z:", z.String())

	publicWitness := makePublicWitness(x, y, z)

	k := ksum(vkBn, x, y, z)
	D := negG1(&k)

	forged := &g16.Proof{
		Ar:            vkBn.G1.Alpha,
		Bs:            vkBn.G2.Beta,
		Krs:           curve.G1Affine{},
		Commitments:   fakeCommitmentsWithSum(D),
		CommitmentPok: curve.G1Affine{},
	}

	if err := groth16.Verify(forged, vk, publicWitness); err != nil {
		panic(fmt.Sprintf("local forged proof invalid: %v", err))
	}

	fmt.Println("[+] local forged proof verified")

	proofHex := proofToHex(forged)
	fmt.Println("[+] proof hex length:", len(proofHex))

	res := submit(ch.Seed, proofHex)
	fmt.Print(res)
}
```

## Menjalankan Exploit

Solver dijalankan dengan:

```bash
go run solve.go
```

Output akhirnya:

```text
[+] local forged proof verified
Flag is: L3AK{1_Plus_1_EquAls_3_gaMMa4637_Linear663_delTA6926_113377}
```

