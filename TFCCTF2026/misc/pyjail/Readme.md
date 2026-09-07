# pyjail

## Metadata

- CTF: TFCCTF 2026
- Category: misc / pyjail
- Local flag: `TEST{flag}`

## Solution

The jail keeps only lowercase letters and `:_.[],`, then rejects `ass`, `typ`, and
`als`.  The payload uses list-comprehension destructuring as assignment to mutate a
`FileFinder` class recovered from `sys.path_hooks`.

It reconstructs `/flag.txt`, imports `ctypes` and `functools` without forbidden
identifiers, and calls `pidfd_open(1)` followed by `pidfd_getfd` to duplicate the
accepted client socket from the jail process.  The flag is read with the recovered
built-in `open` and written directly to that duplicated socket with `os.write`.

`solve.py` is self-contained; it does not depend on `test.py` or any debug helper.
The local process uses accepted descriptor 4 by default.  The remote wrapper used
descriptor 6 for the solved instance, so set `PARENT_FD=6` there.

## Usage

Start the local service with the supplied capability and run the solver:

```bash
./run.sh
HOST=127.0.0.1 PORT=1234 python3 solve.py
```

For the remote instance:

```bash
PARENT_FD=6 HOST=special.thefewchosen.com PORT=30130 python3 solve.py
```

The solved remote flag was:

```text
TFCCTF{i_hope_this_is_not_the_last_jail}
```
