# Programming 101 (PWN) - Detailed Writeup

## Challenge Information
- Category: `pwn`
- Name: `Programming 101`
- Description: `I finally learned how to use malloc, would you check this program for me?`
- Remote: `nc chall.k1nd4sus.it 30500`

## Files Provided
- `main` (ELF binary)
- `libc.so.6` (custom libc, Ubuntu GLIBC 2.31)
- `ld.so.2` (custom loader)
- `run.sh` and `Dockerfile`

## 1. Initial Recon

### Binary protections
Running `checksec` on `main` shows:
- Full RELRO
- Canary enabled
- NX enabled
- PIE enabled
- SHSTK and IBT enabled

So a classic direct stack BOF is not the easiest route (there is a vulnerable stack function, but canary + PIE + NX makes it less practical without more leaks).

### Main behavior
The program is a small heap manager with menu options:
1. Allocate
2. Edit
3. View
4. Delete
5. Vulnerable function
6. Exit

It stores pointers and sizes in global arrays (`chunks[]`, `sizes[]`) and an index counter `count`.

## 2. Static Analysis

Relevant functions discovered:
- `allocate()`
- `edit` logic inside `main()` case 2
- `view()`
- `delete()`
- `vuln()`

### Key bugs

1. **Use-After-Free (UAF)**
`delete()` calls `free(chunks[idx])` but never sets `chunks[idx] = NULL`.
So index is still considered valid and can still be:
- viewed (`puts(chunks[idx])`)
- edited (`read(0, chunks[idx], sizes[idx])`)
- freed again

2. **Double Free primitive**
Because pointer is not nulled, same chunk can be freed multiple times.

3. **Arbitrary write into freed chunks**
Edit operation works on freed memory. This lets us tamper allocator metadata stored in freed chunk user area (tcache fd/key fields).

4. **Leaky view**
`view()` prints chunk contents with `puts()`. For freed unsorted-bin chunks, first qword contains a libc pointer, usable as libc leak.

## 3. Dynamic Analysis & Heap Behavior

### Libc leak method
Allocate a large chunk (`0x500`) and another small guard chunk to prevent top-chunk consolidation.
When freeing the large chunk, it enters unsorted bin.
First 8 bytes become `main_arena+0x60` pointer.

Then `view(index)` prints bytes from the freed chunk, giving leak.

For the provided libc, offset is:
- `main_arena+0x60` = `libc + 0x1ecbe0`

So:
- `libc_base = leak - 0x1ecbe0`

### Why this exploit path works with modern mitigations
- No GOT overwrite needed (Full RELRO).
- No stack overwrite needed (canary + NX avoided).
- We use heap metadata corruption + libc hooks.

## 4. Exploitation Strategy

Goal: execute command to read flag.

Chosen chain:
1. Leak libc via unsorted-bin UAF read.
2. Build tcache double-free state for size `0x90` (`malloc(0x80)`).
3. Poison freelist so an allocation returns address `__free_hook - 8`.
4. Write `system` to `__free_hook`.
5. Allocate chunk containing command string and `free()` it.
6. Because `__free_hook == system`, `free(ptr)` becomes `system(ptr)`.

### Tcache dup trick used
For chunks `a` and `b` of same size:
- `free(a)`
- `free(b)`
- UAF edit on `a` to clear key (`p64(0)+p64(0)`) to bypass tcache double-free check
- `free(a)` again

Now list behaves like: `a -> b -> a`

Then poison `b->fd` by editing freed `b` with `__free_hook-8`.
Three `malloc(0x80)` calls return:
- first: `a`
- second: `b`
- third: `__free_hook-8`

At third allocation, we write:
- padding qword
- `system` qword at `__free_hook`

## 5. Final Solver

Solver file: `solve.py`

It works both locally and remotely:
- Local: `python3 solve.py`
- Remote: `python3 solve.py REMOTE=1`

The solver automatically:
- leaks libc
- poisons tcache
- overwrites `__free_hook`
- executes `cat /app/flag.txt || cat flag.txt || cat /srv/app/flag.txt`
- extracts and prints `KSUS{...}` if present

## 6. Reproduced Result

Flag obtained from remote service:

`KSUS{TLS_15_n07_7r4n5p0r7_l4y3r_53cur17y}`

## 7. Notes

- The stack `vuln()` overflow exists but was unnecessary for fastest reliable solve.
- Heap path is deterministic with provided libc 2.31 and this binary's menu logic.
- This challenge is mainly about understanding UAF + double-free and leveraging allocator internals for code execution.
