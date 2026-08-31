# BlockJail Writeup

## Challenge

- Nama: `BlockJail`
- Kategori: `Misc / Blockchain`
- Flag: `COMPFEST18{I_guess_bro_here_is_relatively_secure_mirror_flag_you_have_searched_for_0f95fd47}`

## Ringkasan

Target solve ada di `Setup.isSolved()`:

1. `TARGET.pathOpened()` harus `true`
2. balance `TARGET` harus `0`
3. `PalaceVault(PALACE).isSolved()` harus `true`

Jadi exploit harus:

1. mendaftarkan `agent` yang lolos validasi runtime `BlockJail`
2. memanggil `openPath()`
3. memanggil `infiltrate(card)` dengan card yang benar supaya `PALACE` solved
4. memanggil `stealHeart()` untuk mengosongkan balance `TARGET`

## Analisis `BlockJail`

File utama:

- [BlockJail.sol](/home/nata/ctf/Compfest18/blockchain/blockjail/BlockJail.sol)
- [Setup.sol](/home/nata/ctf/Compfest18/blockchain/blockjail/Setup.sol)

Fungsi penting di `BlockJail`:

```solidity
function enter() external {
    if (agent != address(0) || msg.sender.code.length == 0) revert InvalidAgent();
    _validateAgentRuntime(msg.sender);
    agent = msg.sender;
    beneficiary = tx.origin;
}
```

Artinya:

- `agent` harus kontrak
- runtime code kontrak itu harus lolos `_validateAgentRuntime`

Constraint validasi runtime:

- ukuran runtime `<= 36` byte
- hanya opcode tertentu yang diizinkan
- harus ada tepat satu `DELEGATECALL`
- harus ada operand `PUSH` yang menunjuk ke address kontrak lain
- address implementasi itu harus cukup kecil:
  `operand <= type(uint144).max`

Intinya challenge memaksa kita pakai tiny proxy yang:

- sangat kecil
- punya satu `DELEGATECALL`
- delegate ke implementation contract dengan vanity address yang 16 bit teratas nol

## Agent yang Dipakai

Runtime proxy yang dipakai:

```text
363d3d373d3d3d363d73<20-byte-impl>5af400
```

Sifat runtime ini:

- copy calldata
- `DELEGATECALL` ke implementation
- `STOP`

Panjang total:

- 10 byte prefix
- 20 byte implementation address
- 3 byte suffix
- total `33` byte

Jadi lolos batas `MAX_AGENT_SIZE = 36`.

Supaya lolos validator `hasVanityImplementation`, implementation tidak dideploy dengan `CREATE` biasa, tapi lewat `CREATE2` sampai dapat address yang nilainya `<= 2^144 - 1`.

## Analisis `PalaceVault`

Source `PalaceVault.sol` tidak diberikan, jadi analisis dilakukan dari bytecode on-chain.

Fakta penting dari reversing:

- `beginInfiltration(bytes)` hanya bisa dipanggil oleh `TARGET`
- input card harus panjang `5`
- lima byte card disimpan ke slot `4..8`
- setelah itu ada dispatcher 4 langkah berdasarkan isi card
- solve terjadi bila urutan transisi state internal tepat

Setelah tracing dan simulasi state machine, card yang valid adalah:

```text
0001030001
```

Card ini tervalidasi dengan `eth_call` langsung ke `PALACE` memakai:

- `from = TARGET`
- `to = PALACE`
- calldata `beginInfiltration(0x0001030001)`

Call tersebut sukses tanpa revert, sedangkan candidate lain revert dengan custom error `0xab4a5c25`.

## Langkah Exploit

Implementation contract cukup punya helper berikut:

```solidity
interface IBlockJail {
    function enter() external;
    function openPath() external;
    function infiltrate(bytes calldata card) external returns (bytes memory);
    function stealHeart() external;
}

contract Impl {
    function enter(address target) external {
        IBlockJail(target).enter();
    }

    function open(address target) external {
        IBlockJail(target).openPath();
    }

    function infiltrateOnly(address target, bytes calldata card) external {
        IBlockJail(target).infiltrate(card);
    }

    function steal(address target) external {
        IBlockJail(target).stealHeart();
    }
}
```

Urutan exploit:

1. Deploy `Factory`
2. Cari salt `CREATE2` sampai implementation address punya prefix `0x0000`
3. Deploy `Impl` lewat `Factory.deploy(code, salt)`
4. Deploy proxy 33-byte yang delegate ke implementation
5. Panggil `proxy -> enter(TARGET)`
6. Panggil `proxy -> open(TARGET)`
7. Panggil `proxy -> infiltrateOnly(TARGET, 0x0001030001)`
8. Panggil `proxy -> steal(TARGET)`

## Verifikasi On-Chain

Pada instance solve final:

- `TARGET = 0xa7971caF6c753f68C75FC5f903DBE5eB00747988`
- `PALACE = 0x66d7e5C148AF299D0447DDEd1BBC06fBA6AA0D4d`

State setelah exploit:

- `agent = 0xA4691ae5bB6475D3Fdb17Bb78B8e7eb15ADa1A33`
- `pathOpened = true`
- `PALACE.isSolved() = true`
- balance `TARGET = 0`
- balance `PALACE = 0`
- `Setup.isSolved() = true`

Transaksi penting:

1. Deploy factory  
   `0x6f4465b88fdb3fe7cd3c7fe65450a3434ce26eb3acd924e40807439d53cc92f3`
2. Deploy implementation  
   `0x953f2281e7172526cfeb06a0af544a5da5176a7d24cb8fa4c3aef702adc48a6e`
3. Deploy proxy  
   `0xa2890c0410f1e2477181cb283cd752b3b0b278ce6d458680fcd950ae1da76602`
4. `enter()`  
   `0x1c709c8af7041a42d2a8852b76eeb2b9b8c0e558bcaa5c0d3fda7a4dddc09f4d`
5. `openPath()`  
   `0x92e31b86bf3c979521fa982a6d8568cec12a74d733d6e538cff278e47ed08a37`
6. `infiltrate(card)`  
   `0x33eaf23b93a7b052a083d3716a03bc0becfa59b6f98df1be5bd78258da899c76`
7. `stealHeart()`  
   `0xae33399f38fe0f6a45292e83b6739b1740c29ca0c72dc2b17b632d2be7dd67db`

## Script

Solver yang dipakai ada di:

- [solve.py](/home/nata/ctf/Compfest18/blockchain/blockjail/solve.py)

Default script sekarang sudah memakai:

- card yang benar: `0001030001`
- chain id `31337`
- gas price statis
- override instance via environment variable

Contoh pakai:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Atau untuk instance lain:

```bash
RPC_URL=http://host:port/uuid \
PRIVKEY=... \
SETUP_CONTRACT_ADDR=... \
TARGET_ADDR=... \
PALACE_ADDR=... \
CARD_HEX=0001030001 \
python3 solve.py
```

## Flag

```text
COMPFEST18{I_guess_bro_here_is_relatively_secure_mirror_flag_you_have_searched_for_0f95fd47}
```
