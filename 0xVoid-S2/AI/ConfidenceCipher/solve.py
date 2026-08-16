import csv

out = ""

with open("confidence_log.csv") as f:
    rows = csv.DictReader(f)

    for r in rows:
        c = int(r["cipher"])
        k = int(r["confidence_percent"])
        out += chr(c ^ k)

print(out)

