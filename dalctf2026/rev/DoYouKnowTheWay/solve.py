import re
from pwn import *

context.arch = 'amd64'

def rol8(val, count):
    count %= 8
    return ((val << count) | (val >> (8 - count))) & 0xFF

def ror8(val, count):
    count %= 8
    return ((val >> count) | (val << (8 - count))) & 0xFF

elf = ELF('./checker_unpacked')

def solve_func(func_name, idx):
    addr = elf.symbols[func_name]
    code = elf.disasm(addr, 0x150) # Longer disassembly just in case
    lines = code.split('\n')
    
    ops = []
    target = None
    
    def get_imm(line):
        match = re.search(r', (0x[0-9a-f]+|[0-9]+)', line)
        if match:
            val = int(match.group(1), 16 if '0x' in match.group(1) else 10)
            return val
        return None

    rol8_addr = hex(elf.symbols['rol8'])
    ror8_addr = hex(elf.symbols['ror8'])
    
    load_seen = False
    for i, line in enumerate(lines):
        if 'movzx' in line and ('BYTE PTR [rax]' in line or 'BYTE PTR [rdx]' in line):
            load_seen = True
            continue
        if not load_seen:
            continue
        
        if 'cmp' in line:
            if 'cmp    al, dl' in line:
                for prev_line in reversed(lines[:i]):
                    if 'mov    edx,' in prev_line:
                        target = get_imm(prev_line) & 0xFF
                        break
            else:
                target = get_imm(line) & 0xFF
            break
            
        if 'xor    eax,' in line:
            ops.append(('xor', get_imm(line)))
        elif 'add    eax, eax' in line:
            ops.append(('mul', 2))
        elif 'add    eax, edx' in line:
            ops.append(('add_orig', None))
        elif 'add    eax,' in line:
            ops.append(('add', get_imm(line)))
        elif 'sub    eax, edx' in line:
            ops.append(('sub_orig', None))
        elif 'sub    eax,' in line:
            ops.append(('sub', get_imm(line)))
        elif 'shl    eax,' in line:
            ops.append(('shl', get_imm(line)))
        elif 'not    eax' in line:
            ops.append(('not', None))
        elif 'movzx  eax, al' in line:
            ops.append(('trunc', None))
        elif 'call' in line:
            if rol8_addr in line:
                count = 0
                for prev_line in reversed(lines[:i]):
                    if 'mov    esi,' in prev_line:
                        count = get_imm(prev_line)
                        break
                ops.append(('rol8', count))
            elif ror8_addr in line:
                count = 0
                for prev_line in reversed(lines[:i]):
                    if 'mov    esi,' in prev_line:
                        count = get_imm(prev_line)
                        break
                ops.append(('ror8', count))
             
    for b in range(256):
        val = b
        orig = b
        for op, imm in ops:
            if op == 'xor':
                val ^= imm
            elif op == 'add':
                val += imm
            elif op == 'sub':
                val -= imm
            elif op == 'rol8':
                val = rol8(val & 0xFF, imm)
            elif op == 'ror8':
                val = ror8(val & 0xFF, imm)
            elif op == 'mul':
                val *= imm
            elif op == 'shl':
                val <<= imm
            elif op == 'add_orig':
                val += orig
            elif op == 'sub_orig':
                val -= orig
            elif op == 'not':
                val = ~val
            elif op == 'trunc':
                val &= 0xFF
            # Intermediate truncation happens in some places but not all.
            # In C, it's 32-bit arithmetic.
            val &= 0xFFFFFFFF
            
        if (val & 0xFF) == target:
            return chr(b)
    return '?'

flag = ""
for i in range(44):
    func_name = f"f_{i}"
    char = solve_func(func_name, i)
    flag += char
    print(f"Found {char} for {func_name}")

print(f"Flag: {flag}")
