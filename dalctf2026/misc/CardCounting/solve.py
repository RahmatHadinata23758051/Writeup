
import requests

s_const = 1664525
i_const = 1013904223
o_const = 2147483647

def h(r):
    t = 63 & (r >> 4)
    e = t & 15
    if e > 9:
        e = 16 - e
    n = 3 & (t >> 4)
    new_r = (r * s_const + i_const) & o_const
    val = (n + e * 4 + 16) % 40
    return val, e, new_r

def get_level_sum(seed, count):
    current_r = seed
    total_sum = 0
    for _ in range(count):
        _, e, current_r = h(current_r)
        total_sum += (e + 1)
    return total_sum, current_r

url = "https://dalctf-card-counting-204-64616c.instancer.dalctf2026.com"
session = requests.Session()

# Start Game
resp = session.get(f"{url}/api/start_game")
data = resp.json()
seed = data['seed']
print(f"Start seed: {seed}")

# Levels
# M: 4
# y: 8
# _: 25
# g: 16*5 = 80
# p: 50
# v: 100
# I: 1000
level_counts = [4, 8, 25, 80, 50, 100, 1000]

for i, count in enumerate(level_counts):
    level_sum, _ = get_level_sum(seed, count)
    print(f"Level {i+1} ({count} cards), Sum: {level_sum}")
    
    resp = session.post(f"{url}/api/submit", data={'answer': level_sum})
    result = resp.json()
    print(f"Result: {result}")
    
    if 'error' in result and result['error']:
        print(f"Error: {result['error']}")
        break
    
    if 'flag' in result and result['flag']:
        print(f"FLAG: {result['flag']}")
        break
    
    if 'seed' in result:
        seed = result['seed']
    else:
        print("No seed in response, game might be over or failed.")
        break
