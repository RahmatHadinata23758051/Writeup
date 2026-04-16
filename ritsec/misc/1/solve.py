import dns.resolver
import dns.query
import dns.message

subdomains_to_check = []  # isi dari hasil enum step sebelumnya
results = []

for sub in subdomains_to_check:
    try:
        ans = dns.resolver.resolve(sub, 'TXT', tcp=True)
        for r in ans:
            txt = r.to_text()
            results.append((len(txt), sub, txt))
    except:
        pass

results.sort(reverse=True)
print(results[0])  # longest = flag!
