import base64
import requests

# Dictionary of all base64 fragments found in EXIF tags of the two images
fragments = {
    '267.jpg': {
        'Image Description': ('tag', 'dHUu', 'tu.'),
        'Image Description': ('v', 'Njk=', '69'),
        'Copyright': ('c', 'Q3N2', 'Csv'),
        'Lens Model': ('lens', 'aHR0', 'htt'),
        'Artist': ('artist', 'Ly9w', '//p'),
        'Software': ('software', 'b20v', 'om/'),
        'User Comment': ('ref', 'cnUv', 'ru/'),
        'Host Computer': ('host', 'ZWJp', 'ebi')
    },
    '678.jpg': {
        'Image Description': ('k', 'cy0x', 's-1'),
        'Image Description': ('q', 'Ly9r', '//k'),
        'User Comment': ('id', 'dWJz', 'ubs'),
        'Lens Model': ('rev', 'U3VC', 'SuB'),
        'Copyright': ('copyright', 'cEs=', 'pK'),
        'Artist': ('team', 'cHM6', 'ps:'),
        'Software': ('software', 'bi5j', 'n.c'),
        'Host Computer': ('host', 'YXN0', 'ast')
    }
}

# The fragments form two main URLs:
# 1. https://kubstu.ru/s-169
kubstu_url = "htt" + "ps:" + "//k" + "ubs" + "tu." + "ru/" + "s-1" + "69"
print(f"[*] Found URL 1: {kubstu_url}")

# 2. https://pastebin.com/
pastebin_url = "htt" + "ps:" + "//p" + "ast" + "ebi" + "n.c" + "om/"
print(f"[*] Found URL 2: {pastebin_url}")

# The remaining decoded fragments are 'Csv', 'SuB', 'pK'
# These total exactly 8 characters, matching a Pastebin ID format.
pastebin_id = "SuBCsvpK"
final_url = pastebin_url + "raw/" + pastebin_id
print(f"[*] Fetching final flag from: {final_url}")

response = requests.get(final_url)
if response.status_code == 200:
    print(f"[*] Flag found: {response.text.strip()}")
else:
    print("[-] Failed to fetch flag from pastebin.")
