# Buat file decode.py
mapping = {
    "Backup completed successfully.": "0",
    "Did you check the logs?": "1",
    "Did you finish the assignment?": "2",
    "Network latency seems stable.": "3",
    "Let's push the update tomorrow.": "4",
    "Server response looks strange.": "5",
    "System health check OK.": "6",
    "Testing connection again.": "7"
}

with open("message_sequence.txt", "r") as f:
    lines = [l.strip() for l in f.readlines() if l.strip() in mapping]
    octal_str = "".join([mapping[l] for l in lines])

print(f"Octal: {octal_str}")
# Convert octal to bytes
try:
    for i in range(0, len(octal_str), 3):
        chunk = octal_str[i:i+3]
        print(chr(int(chunk, 8)), end="")
    print()
except:
    print("\n[!] Coba geser offset atau cek jumlah pesan.")
