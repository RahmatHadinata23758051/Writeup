# Did you get the HINT

Viktor "Crypt" has shared a suspicious program to Dimitri Ieba.
We suspect the program to contain the password to access a XSS server.
Your goal his to find the hidden flag in the HINT.elf program.

## Notes

The program contains two flags.

You might use [spike][1] to run the program

```shell
spike --isa=rv32imac HINT.elf
```

[1]: https://github.com/riscv-software-src/riscv-isa-sim
