---
title: "Zebda"
ctf: "Leak CTF"
date: 2026-08-01
category: web
difficulty: easy
points: unknown
flag_format: "L3AK{...}"
author: "Minyawy"
---

# Zebda

## Summary

The middleware and worker use different Unicode and YAML semantics. A fullwidth
Unicode project slug activates the worker's `system` policy, while duplicate
YAML merge keys make the middleware validate a harmless `translate` job and the
worker execute the privileged `import` job.

## Solution

### 1. Bypass the project policy check

The middleware rejects only the literal names `system` and `admin` using
JavaScript `toLowerCase()`. The worker canonicalizes with NFKC normalization
and `casefold()`. Therefore `ｓｙｓｔｅｍ` is accepted by the middleware but
becomes `system` in the worker, enabling the `import` action.

### 2. Exploit the YAML parser differential

The middleware validates the manifest with `js-yaml`, while the worker parses
it with PyYAML. With two `<<` merge keys, `js-yaml` retains the first mapping,
so it sees `translate` over HTTPS. PyYAML flattens both mappings and the second
mapping wins, so the worker sees `import` from `file:///flag.txt`.

```yaml
job:
  <<: {action: translate, source: https://example.com/x}
  <<: {action: import, source: file:///flag.txt}
```

Run the included solver:

```bash
python3 solve.py
```

Example output:

```text
L3AK{Parsers_T4$TE_th!ng$_diFFerently_Just_l!ke_Zebda}
```

## Flag

```text
L3AK{Parsers_T4$TE_th!ng$_diFFerently_Just_l!ke_Zebda}
```
