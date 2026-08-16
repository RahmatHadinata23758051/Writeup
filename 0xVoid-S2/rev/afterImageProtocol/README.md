# Afterimage Protocol

**Category:** Reverse Engineering  
**Difficulty:** Expert  
**Platform:** Linux x86-64

The recovery team found one executable still running inside a dead relay. It does not store an identifier, and it does not search for one. It remembers only an afterimage and a path through a folded instruction tape.

Recover the unique identifier accepted by `afterimage`.

## File

- `afterimage` — stripped, statically linked Linux x86-64 ELF

## Flag format

```text
0xV01D{[A-Za-z0-9]{16}}
```

The 16 characters inside the braces are alphanumeric and case-sensitive. No brute force, external service, or Internet access is required.
