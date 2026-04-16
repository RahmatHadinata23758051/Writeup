numbers = "18 5 25 11 10 1 22 9 11 9 3 5 12 1 14 4"
# Konversi angka ke Huruf Kapital (ASCII 65 adalah 'A')
flag_content = "".join([chr(int(n) + 64) for n in numbers.split()])

print(f"uni6{{{flag_content}}}")
