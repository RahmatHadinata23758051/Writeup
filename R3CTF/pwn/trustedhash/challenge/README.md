# TrustedHash solver

Run these scripts **inside the player VM as root**.

## Exploit flow

1. `recover_auth.py` snapshots the TPM event log, stops the normal agent, then
   enters ACPI S3 with the TPM driver detached. The resume reset clears volatile
   PCR state but keeps persistent objects.
2. The script replays measured-boot SHA-256 events until the policy on persistent
   object `0x81010021` matches, then unseals the 32-byte authorization for the
   persistent module signer at `0x81010020`.
3. After a normal reboot restores the expected PCR baseline, `launch.sh` runs the
   genuine agent privately on port 31338 and exposes `solve.py` on port 31337.
4. The proxy keeps the genuine EK/AK activation flow, substitutes a software RSA
   decrypt key, signs a forged `TPMS_ATTEST` with the live AK, and re-signs the
   complete transcript with the recovered module-signer authorization.
5. The checker encrypts the flag to the substituted RSA key. The proxy decrypts
   it, returns the correct SHA-256, and saves the plaintext.

## Stage 1: recover module-signer authorization

```sh
cd /root/trustedhash-solver
python3 recover_auth.py
```

The VM suspends for about eight seconds. SSH normally survives, but running from
VNC/serial is safer. Success ends with output similar to:

```text
[+] recovered module signer auth: ...
[+] saved to /root/trustedhash/module_signer_auth.bin
```

PCRs are intentionally no longer at the checker baseline after replay. Reboot:

```sh
reboot
```

If the script reports that S3 did not clear the selected PCRs, reboot immediately
before retrying; do not launch the proxy from the modified PCR state.

## Stage 2: launch proxy

After the VM boots normally:

```sh
cd /root/trustedhash-solver
./launch.sh
tail -f /root/trustedhash/logs/proxy.log
```

Wait for the periodic checker. On success:

```text
[+] recovered plaintext: r3ctf{...}
<FLAG>r3ctf{...}</FLAG>
```

The recovered value is also stored at:

```sh
cat /root/trustedhash/flags.txt
```

## Files

- `recover_auth.py` — vTPM S3 reset, event-log replay, policy unseal.
- `solve.py` — malicious attestation proxy and RSA flag decryptor.
- `launch.sh` — starts the genuine backend and public proxy.
