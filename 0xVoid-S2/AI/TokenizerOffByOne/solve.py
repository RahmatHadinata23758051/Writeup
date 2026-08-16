import json

data=json.load(open("token_dump.json"))

vocab=data["vocab_zero_indexed"]
ids=data["generated_token_ids"]

flag="".join(vocab[i-1] for i in ids)

print(flag)
