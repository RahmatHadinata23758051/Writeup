import csv, math

tokens=[]
queries=[]

with open("embeddings.csv") as f:
    for r in csv.DictReader(f):
        item=(r["label"], float(r["x"]), float(r["y"]))

        if r["kind"]=="token":
            tokens.append(item)
        else:
            queries.append((r["label"], float(r["x"]), float(r["y"])))

queries.sort()

out=""

for q,x,y in queries:
    best=min(
        tokens,
        key=lambda t: math.sqrt((x-t[1])**2+(y-t[2])**2)
    )
    out += best[0]

print(out)
