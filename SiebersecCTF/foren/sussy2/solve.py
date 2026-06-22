import base64

def rot13(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        elif '0' <= char <= '9':
            result += chr((ord(char) - ord('0') + 5) % 10 + ord('0'))
        else:
            result += char
    return result

def main():
    # Original string found in classes4.dex
    # Pattern: 0C + Base64 encoded (ROT13/ROT5 applied) flag
    # Note: '0C' is likely a length prefix in the DEX data. 
    # The actual base64 starts with 'CmZw...'
    encoded_str = "CmZwZ3N7VnNfMnU4ZThfajlmXzlhXzhhcWM1dmEyISEhfQ=="
    
    try:
        # Step 1: Base64 Decode
        # Using URL-safe characters if necessary (though this string is standard)
        decoded_bytes = base64.b64decode(encoded_str)
        intermediate = decoded_bytes.decode('utf-8', errors='ignore')
        print(f"Intermediate (Base64 Decoded): {intermediate}")
        
        # Step 2: Apply ROT13 (for letters) and ROT5 (for numbers)
        flag = rot13(intermediate)
        print(f"Final Flag: {flag}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
