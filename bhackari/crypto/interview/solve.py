#!/usr/bin/env python3
import hashlib
import itertools
from pwn import *

# --- Challenge Data ---
FLAG_HOST = "interview.challs.ctf.bhackari.it"
FLAG_PORT = 10001

statement = (
    "Venice is a * city . The food there is * . People in there are * . "
    "The weather is * . The architecture is * . The canals are * . "
    "The nightlife is * . The art is * . The history is * . "
    "The shopping is * . The transportation is * . The hotels are * . "
    "The festivals are * . The parks are * . The safety is * . "
    "The cost is * . The music is * . The sports are * . The schools are * . "
    "The hospitals are * . The streets are * . The squares are * . The monuments are * . "
    "The museums are * . The churches are * . The bridges are * . The gardens are * . "
    "The lakes are * . The mountains are * . The rivers are * . The forests are * . "
    "The animals are * .")

good_words = ["cool", "great", "friendly", "sunny", "beautiful", "romantic", "gorgeous", "lively", "artistic", "historic", "trendy", "convenient", "comfortable", "good", "upbeat", "heavenly",  "stylish", "fashionable",
              "delicious", "tasty", "fresh", "authentic", "exciting", "fascinating", "vibrant", "efficient", "luxurious", "fun", "relaxing", "safe", "affordable", "amazing", "wonderful", "charming", "snazzy", "swanky",
              "delightful", "enchanting", "inviting", "captivating", "breathtaking", "spectacular", "stunning", "magnificent", "festive", "welcoming", "hospitable", "clean", "organized", "modern", "innovative",
              "eco-friendly", "sustainable", "family-friendly", "adventurous", "cultural", "picturesque", "scenic", "tranquil", "serene", "idyllic", "legendary", "mythical", "paradisiacal", "utopian",
              "divine", "exquisite", "splendid", "radiant", "joyful", "cheerful", "glorious", "impressive", "outstanding", "superb", "marvelous", "fantastic", "brilliant", "stellar", "positive", "optimistic",
              "resplendent", "flourishing", "prosperous", "thriving", "robust", "dynamic", "energetic", "vivacious", "zestful", "peppy", "buoyant", "gleeful", "mirthful", "jubilant", "exuberant","dapper",
              "admirable", "commendable", "laudable", "notable", "noteworthy", "exceptional", "phenomenal", "majestic", "regal", "noble", "pristine", "untarnished", "unblemished", "immaculate", "swish",
              "spotless", "crisp", "refreshing", "soothing", "harmonious", "peaceful", "calm", "gentle", "mellow", "graceful", "elegant", "refined", "cultured", "sophisticated", "polished", "chic"]

bad_words = ["boring", "bad", "unfriendly", "rainy", "ugly", "dull", "uncomfortable", "overcrowded", "expensive", "dirty", "noisy", "crowded", "unsafe", "slow", "inefficient","abandoned", "infested",
             "terrible", "awful", "disgusting", "inedible", "bland", "overrated","depressing", "dreary", "gloomy", "unpleasant", "horrible", "lousy", "pathetic", "crumbling", "derelict", "chilly",
             "hideous", "grimy", "filthy", "seedy", "squalid", "dingy", "chaotic", "disorganized", "polluted", "outdated", "obsolete", "ineffective", "inconvenient", "unreliable", "decrepit", "raw",
             "dangerous", "overpriced", "unaffordable", "stressful", "frustrating", "disappointing", "unwelcoming", "hostile", "rude", "impolite", "unhygienic", "unsanitary", "dilapidated", "run-down",
             "atrocious", "appalling", "dreadful", "ghastly", "horrendous", "abysmal", "wretched", "deplorable", "lamentable", "dire", "grim", "bleak", "forlorn", "hopeless", "desolate", "neglected",
             "ravaged", "ruined", "wrecked", "shabby", "tattered", "battered", "mangled", "mutilated", "scarred", "marred", "defaced", "defiled", "tainted", "corrupt", "vile", "vicious", "nippy",
             "malicious", "malevolent", "sinister", "ominous", "menacing", "threatening", "perilous", "hazardous", "risky", "treacherous", "precarious", "unstable", "volatile", "explosive", "outraged",
             "tumultuous", "turbulent", "stormy", "tempestuous", "wild", "fierce", "savage", "brutal", "barbaric", "cruel", "ruthless", "merciless", "pitiless", "cold", "icy", "frigid",  "indignant",]

# --- Pre-computation Optimization ---
statement_fmt = statement.replace("*", "{}")

# Fix 20 words pertama, permutasikan 12 kata terakhir
base_good = good_words[:20]
perm_good_pool = good_words[20:32]

base_bad = bad_words[:20]
perm_bad_pool = bad_words[20:32]

# Pre-format bagian fixed untuk menghemat siklus CPU
prefix_good = statement_fmt.format(*(base_good + ["{}"] * 12))
prefix_bad = statement_fmt.format(*(base_bad + ["{}"] * 12))

def get_hash(msg: bytes) -> int:
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h[-6:], 'big')

def solve():
    print("[*] Generating Meet-in-the-Middle dictionary...")
    print("[*] (Ini butuh waktu ~30-40 detik dan RAM ~1.5 GB)")
    
    good_dict = {}
    good_iter = itertools.permutations(perm_good_pool)
    
    # Target 16 juta hashes -> Memberikan probabilitas collision tinggi
    TARGET_GOOD = 16_000_000

    for i in range(TARGET_GOOD):
        p = next(good_iter)
        msg = prefix_good.format(*p).encode('utf-8')
        h = get_hash(msg)
        good_dict[h] = p
        
        if (i + 1) % 4_000_000 == 0:
            print(f"[-] Tersimpan {i + 1} good hashes...")

    print(f"[*] Selesai. Ukuran dictionary: {len(good_dict)}")
    print("[*] Mencari hash collision dari bad_words...")

    bad_iter = itertools.permutations(perm_bad_pool)
    collision = None

    for i, p in enumerate(bad_iter):
        msg = prefix_bad.format(*p).encode('utf-8')
        h = get_hash(msg)

        if h in good_dict:
            print(f"\n[+] COLLISION DITEMUKAN pada iterasi ke-{i}!")
            print(f"[+] Matching Hash: {hex(h)}")
            
            good_msg = prefix_good.format(*good_dict[h])
            bad_msg = prefix_bad.format(*p)
            collision = (good_msg, bad_msg)
            break

        if (i + 1) % 4_000_000 == 0:
            print(f"[-] Telah mengecek {i + 1} bad hashes...")

    if not collision:
        print("[-] Gagal menemukan collision. Coba tingkatkan TARGET_GOOD.")
        return

    print("\n[*] Mengirim payload ke server...")
    io = remote(FLAG_HOST, FLAG_PORT)

    io.recvuntil(b"Enter your statement for Journalist 1: ")
    io.sendline(collision[0].encode())

    io.recvuntil(b"Enter your statement for Journalist 2: ")
    io.sendline(collision[1].encode())

    print("\n[+] Respons Server:")
    print(io.recvall(timeout=5).decode('utf-8', 'ignore'))

if __name__ == "__main__":
    solve()
