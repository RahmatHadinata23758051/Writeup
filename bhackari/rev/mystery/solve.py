import mystery
import ctypes
import os

# Find the base address of mystery.so
with open("/proc/self/maps", "r") as f:
    for line in f:
        if "mystery.so" in line and "r-xp" in line:
            mapping_start = int(line.split("-")[0], 16)
            elf_base = mapping_start - 0x2000
            break
    else:
        raise Exception("Could not find mystery.so in memory maps")

print(f"Elf base: {hex(elf_base)}")

# Initialize the mystery module (this runs the constructors)
mystery.get_runtime_info()

# Define the helper function types
# All stage helpers have signature: int func(int index)
# Wait, let's check the disassembly again. Yes, edi = index.

stage_helpers = [0x31ec, 0x3271, 0x3304, 0x33ef]
expected_values = []

# We need a way to call these addresses. 
# We can use ctypes.CFUNCTYPE
StageFunc = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32)

for i, offset in enumerate(stage_helpers):
    addr = elf_base + offset
    func = StageFunc(addr)
    val = func(i + 1)
    expected_values.append(val)
    print(f"Stage {i+1} expected value: {val} (hex: {hex(val)})")

# Now submit the stages
for i, val in enumerate(expected_values):
    try:
        mystery.stage(i + 1, val)
        print(f"Stage {i+1} submitted successfully.")
    except Exception as e:
        print(f"Stage {i+1} submission failed: {e}")

# Finally, reveal the flag
try:
    res = mystery.reveal()
    print(f"Reveal result: {res}")
except Exception as e:
    print(f"Reveal failed: {e}")
