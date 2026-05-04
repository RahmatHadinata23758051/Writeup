from pwn import *
from randcrack import RandCrack
import re

def solve():
    # host = 'localhost' # for local testing if I had a server
    # port = 1337
    
    host = 'crypto.cbd2026.cloud'
    port = 1337

    rc = RandCrack()
    r = remote(host, port)

    def get_balance():
        r.recvuntil(b'Balance: ')
        balance = int(r.recvuntil(b' credits').split()[0])
        return balance

    for i in range(624):
        log.info(f"Round {i+1}/624")
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'stake: ', b'1')
        r.sendlineafter(b'number (0-36): ', b'0')
        
        data = r.recvuntil(b'ticket id: ')
        ticket_hex = r.recvline().strip().decode()
        ticket = int(ticket_hex, 16)
        rc.submit(ticket)
        log.debug(f"Ticket: {ticket:08x}")

    balance = get_balance()
    log.info(f"Current balance: {balance}")

    # Now predict
    predicted_ticket = rc.predict_getrandbits(32)
    winning_number = predicted_ticket % 37
    log.info(f"Predicted ticket: {predicted_ticket:08x}, Winning number: {winning_number}")

    # Bet all
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'stake: ', str(balance).encode())
    r.sendlineafter(b'number (0-36): ', str(winning_number).encode())
    
    r.recvuntil(b'ticket id: ')
    actual_ticket_hex = r.recvline().strip().decode()
    log.info(f"Actual ticket: {actual_ticket_hex}")
    
    balance = get_balance()
    log.info(f"New balance: {balance}")
    
    if balance < 50000:
        log.info("Winning one more round to reach 50000...")
        predicted_ticket = rc.predict_getrandbits(32)
        winning_number = predicted_ticket % 37
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'stake: ', str(balance).encode())
        r.sendlineafter(b'number (0-36): ', str(winning_number).encode())
        r.recvuntil(b'ticket id: ')
        balance = get_balance()
        log.info(f"Final balance: {balance}")

    log.info("Buying flag...")
    r.sendlineafter(b'> ', b'3')
    flag_line = r.recvall()
    print(flag_line.decode())

if __name__ == "__main__":
    solve()
