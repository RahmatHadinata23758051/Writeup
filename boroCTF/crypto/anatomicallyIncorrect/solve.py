import re

data = """1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p4 1s2 2s2 2p6 3s2 3p6 1s2 2s2 2p6 3s2 3p6 4s2 3d3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f13 1s2 2s2 2p6 3s2 3p4 1s2 2s2 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d9 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6 6s2 4f14 5d10 6p6 7s2 5f14 6d10 7p3 1s2 2s2 2p6 3s2 3p6 4s2 3d10 4p6 5s2 4d10 5p6"""

tokens = data.split()
configs = []
cur = []

for t in tokens:
    if t == "1s2" and cur:
        configs.append(cur)
        cur = [t]
    else:
        cur.append(t)

configs.append(cur)

nums = []
for cfg in configs:
    nums.append(sum(int(re.search(r"\d+$", x).group()) for x in cfg))

print(nums)
