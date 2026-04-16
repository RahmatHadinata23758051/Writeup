import string

def solve_ancient_signal(morse_input):
    # 1. Dictionary Morse
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z'
    }
    
    # 2. Decode Morse
    decoded_morse = "".join([morse_dict[c] for c in morse_input.split()])
    print(f"Morse Result: {decoded_morse}")
    
    # 3. Reverse String
    reversed_str = decoded_morse[::-1]
    
    # 4. Caesar Shift +3 (Kaisar Kuno)
    def caesar_shift(text, shift):
        alphabet = string.ascii_uppercase
        shifted_alphabet = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet, shifted_alphabet)
        return text.translate(table)

    final_text = caesar_shift(reversed_str, 3)
    return final_text

morse_signal = ".- -... .- -.- .-. .-.. -.-. -.. -..- .. -.-. -... .- .-.. --.. -... .--. --- .-.. .---"
result = solve_ancient_signal(morse_signal)
print(f"Final Text: {result}")
