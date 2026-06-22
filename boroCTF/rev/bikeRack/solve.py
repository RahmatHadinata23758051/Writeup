import subprocess

def solve():
    # Strings extracted from the binary
    s1 = list("1927591750185873109357128735:912357132509713257561029375701027357361:2179327561242142098:980985641877731:238")
    s2 = "187773102385012356629012836224235219768597857"
    
    # Binary manipulation logic:
    # 1. memmove(s1, s1 + 8, 100)
    # 2. strncat(s1, s2, 11)
    
    new_s1 = s1[8:8+100]
    # The original string had length 107. After memmove of 100 bytes from s1+8,
    # the null terminator at s1[107] is moved to s1[99].
    # So the string effectively ends at index 99.
    pin = "".join(new_s1[:99]) + s2[:11]
    
    # Run the binary with the reconstructed PIN
    process = subprocess.Popen(["./chall"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(input=pin)
    
    # Extract flag from output
    for line in stdout.splitlines():
        if "PIN: " in line:
            flag = line.split("PIN: ")[1].strip("\x00")
            print(flag)
            return flag

if __name__ == "__main__":
    solve()
