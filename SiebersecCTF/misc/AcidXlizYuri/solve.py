
import itertools
import binascii

def solve():
    letters = "anjrvudtpw" # 10 unique letters
    # anj * rnnvar * ruvavdtu = jvddpnpnapudntar
    
    for p in itertools.permutations(range(10)):
        mapping = dict(zip(letters, p))
        
        if mapping['a'] == 0 or mapping['r'] == 0 or mapping['j'] == 0:
            continue
            
        anj = mapping['a']*100 + mapping['n']*10 + mapping['j']
        rnnvar = mapping['r']*100000 + mapping['n']*10000 + mapping['n']*1000 + mapping['v']*100 + mapping['a']*10 + mapping['r']
        ruvavdtu = mapping['r']*10000000 + mapping['u']*1000000 + mapping['v']*100000 + mapping['a']*10000 + mapping['v']*1000 + mapping['d']*100 + mapping['t']*10 + mapping['u']
        
        target_val = anj * rnnvar * ruvavdtu
        
        target_str = str(target_val)
        if len(target_str) != 16:
            continue
            
        pattern = "jvddpnpnapudntar"
        match = True
        for i in range(16):
            if target_str[i] != str(mapping[pattern[i]]):
                match = False
                break
        
        if match:
            # jvddpnpnapudntar * (juawupduvuttjvanpnndwpujpwtvvwnwptptdwnwupwnjjvujupn + vjatvntuva)
            
            notes_str = "juawupduvuttjvanpnndwpujpwtvvwnwptptdwnwupwnjjvujupn"
            notes_val = 0
            for char in notes_str:
                notes_val = notes_val * 10 + mapping[char]
                
            emotion_str = "vjatvntuva"
            emotion_val = 0
            for char in emotion_str:
                emotion_val = emotion_val * 10 + mapping[char]
                
            flag_val = target_val * (notes_val + emotion_val)
            hex_val = hex(flag_val)[2:]
            if len(hex_val) % 2 != 0:
                hex_val = '0' + hex_val
            flag = bytes.fromhex(hex_val).decode('utf-8', errors='ignore')
            print(flag)
            return

if __name__ == "__main__":
    solve()
