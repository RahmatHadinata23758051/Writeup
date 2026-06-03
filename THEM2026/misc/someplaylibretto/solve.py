import re

def decode_caesar(text, shift=20):
    result = ""
    for c in text:
        if 'A' <= c <= 'Z':
            result += chr(((ord(c) - 65 - shift) % 26) + 65)
        elif 'a' <= c <= 'z':
            result += chr(((ord(c) - 97 - shift) % 26) + 97)
        else:
            result += c
    return result

NOUNS = [n.lower() for n in ["rose", "flower", "kingdom", "Lord", "plum", "Heaven", "King", "hero", "joy", "angel", "happiness"]]
ADJECTIVES = [a.lower() for a in ["happy", "sweet", "warm", "proud", "brave", "honest", "mighty", "loving", "bold", "good", "gentle", "noble", "lovely", "rich", "sunny", "golden", "charming", "fair"]]

def calculate_expression_value(text, current_val):
    has_thyself = "thyself" in text.lower()
    clean_text = re.sub(r'\b(the sum of|sum of|and|a|an|the)\b', ' ', text, flags=re.IGNORECASE)
    words = clean_text.split()
    total = 0
    current_adjectives = 0
    for word in words:
        word_clean = word.strip("!.,?").lower()
        if word_clean in ADJECTIVES:
            current_adjectives += 1
        elif word_clean in NOUNS:
            total += (2 ** current_adjectives)
            current_adjectives = 0
        elif word_clean == "nothing":
            total = 0
            current_adjectives = 0
        elif word_clean == "thyself":
            current_adjectives = 0
    if has_thyself:
        return current_val + total
    else:
        return total

def parse_spl(content):
    lines = content.split('\n')
    current_value = 0
    output_chars = []
    for line in lines:
        line = line.strip()
        if not line: continue
        match = re.search(r'^(?:Thou|You) art (.*)!$', line)
        if match:
            expr = match.group(1)
            if expr == "nothing":
                current_value = 0
            else:
                current_value = calculate_expression_value(expr, current_value)
        if "Speak thy mind!" in line:
            output_chars.append(chr(current_value % 1114112))
    return "".join(output_chars)

def to_leetspeak(text):
    # s=5, o=0, e=3, a=4, i=1, t=7, g=6
    replacements = {
        's': '5', 'o': '0', 'e': '3', 'a': '4', 'i': '1', 't': '7', 'g': '6', ' ': '_'
    }
    result = ""
    for c in text.lower():
        result += replacements.get(c, c)
    return result

if __name__ == "__main__":
    with open("score.txt", "r") as f:
        encoded_content = f.read()
    
    decoded_content = decode_caesar(encoded_content)
    # Save for reference
    with open("decoded_score.spl", "w") as f:
        f.write(decoded_content)
        
    extracted_text = parse_spl(decoded_content)
    leetspeak_text = to_leetspeak(extracted_text)
    
    flag = f"THEM?!CTF{{{leetspeak_text}}}"
    print(flag)
