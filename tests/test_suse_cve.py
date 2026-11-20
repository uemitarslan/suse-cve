#!/usr/bin/env python3
import json
import os
import subprocess
import sys

BIN = os.path.abspath("bin/suse-cve")

def run_cli(*args):
    proc = subprocess.run(
        [sys.executable, BIN, *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=45,
    )
    return proc.returncode, proc.stdout, proc.stderr

def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"  [PASS] {msg}")

print("=== 1. INPUT SANITIZATION & ERROR HANDLING ===")
rc, out, err = run_cli("15sp7", "CVE-INVALID")
check(rc != 0 and "Invalid CVE identifier" in err, "Rejects malformed CVE ID with non-zero exit code")

rc, out, err = run_cli("15sp7", "cve-2026-97876.", "--mitigate")
check(rc == 0 and "[CVE-2026-97876 |" in out, "Normalizes lowercase CVE and strips trailing punctuation")

rc, out, err = run_cli("CVE-2026-97876", "--json")
data_implicit_all = json.loads(out)
check(rc == 0 and data_implicit_all.get("release") == "all", "Defaults release to 'all' when omitted")

print("\n=== 2. NOT AFFECTED & LIFECYCLE ISOLATION (12sp5) ===")
rc, out, err = run_cli("12sp5", "CVE-2026-97876")
check(rc == 0, "Exits 0 on 12sp5 query")
check("NOT AFFECTED / NO OPEN VULNERABILITY" in out, "Reports NOT AFFECTED status for 12sp5")
check("[NOT AFFECTED]" in out and "12 SP5" in out, "Displays 12 SP5 in [NOT AFFECTED] detail block")
check("15 SP1" not in out.split("[NOT AFFECTED]")[1].split("[MITIGATION")[0], "Does not leak unrelated 15 SP1 rows into 12sp5 detail block")
check("1. No SLES packages affected -- no local workaround required" in out, "Shows single clean no-op workaround for NOT AFFECTED target")
check("Vendor Upstream Mitigation" not in out.split("Recommended SLES Workarounds")[1], "Suppresses upstream workaround commands when target is NOT AFFECTED")

print("\n=== 3. FLAG SEPARATION: DEFAULT vs --mitigate vs --remediate ===")
rc, out_def, _ = run_cli("15sp7", "CVE-2026-114938")
check("Recommended SLES Remediation" in out_def and "Compensating Workarounds" in out_def, "Default mode shows both patch remediation and workarounds")

rc, out_mit, _ = run_cli("15sp7", "CVE-2026-114938", "--mitigate")
check("Recommended SLES Remediation" not in out_mit and "Compensating Workarounds" in out_mit, "--mitigate strictly hides patch remediation block")

rc, out_rem, _ = run_cli("15sp7", "CVE-2026-114938", "--remediate")
check("Recommended SLES Remediation" in out_rem and "Compensating Workarounds" not in out_rem, "--remediate strictly hides compensating workarounds")

rc, out_rem_pend, _ = run_cli("15sp7", "CVE-2026-97876", "--remediate")
check("No official SUSE vendor patch released yet" in out_rem_pend and "--mitigate" in out_rem_pend, "--remediate shows explicit fallback hint when patch is Pending")

print("\n=== 4. AUTOMATION OUTPUTS (--json, --salt-config, --ansible-config) ===")
rc, out_json, _ = run_cli("15sp7", "CVE-2026-97876", "--json")
parsed = json.loads(out_json)
check(rc == 0 and parsed["cve"] == "CVE-2026-97876" and "meta" in parsed, "--json produces valid structured JSON")

rc, out_salt_na, _ = run_cli("12sp5", "CVE-2026-97876", "--mitigate", "--salt-config")
check(rc == 0 and "test.succeed_without_changes:\n    - name:" in out_salt_na, "--salt-config generates valid test.succeed_without_changes state for NOT AFFECTED")

rc, out_ans_mit, _ = run_cli("15sp7", "CVE-2026-97876", "--mitigate", "--ansible-config")
check(rc == 0 and "hosts:" in out_ans_mit and "tasks:" in out_ans_mit, "--ansible-config generates valid Ansible playbook structure")

print("\n=== 5. SIGPIPE / PIPING HYGIENE ===")
rc_ans_na, out_ans_na, _ = run_cli("12sp5", "CVE-2026-97876", "--mitigate", "--ansible-config")
check(rc_ans_na == 0 and "ansible.builtin.debug" in out_ans_na, "--ansible-config generates valid debug no-op task for NOT AFFECTED")

p1 = subprocess.Popen([sys.executable, BIN, "all", "CVE-2026-97876"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
p2 = subprocess.Popen(["head", "-n", "5"], stdin=p1.stdout, stdout=subprocess.PIPE, universal_newlines=True)
p1.stdout.close()
_ = p2.communicate()
p1_err = p1.stderr.read()
p1.stderr.close()
p1.wait()
check("BrokenPipeError" not in p1_err and "Traceback" not in p1_err, "Exits silently without Traceback on SIGPIPE (| head)")

print("\nALL CORE TRIAGE TESTS PASSED SUCCESSFULLY.")

print("\n=== 6. SL MICRO TRANSACTIONAL-UPDATE & REBOOT HANDLING ===")
rc_m_salt, out_m_salt, _ = run_cli("micro6.1", "CVE-2026-98971", "--remediate", "--salt-config")
check(rc_m_salt == 0 and "transactional-update" in out_m_salt, "SL Micro Salt state uses transactional-update instead of raw zypper")

rc_m_ans, out_m_ans, _ = run_cli("micro6.1", "CVE-2026-98971", "--remediate", "--ansible-config")
check(rc_m_ans == 0 and "transactional-update" in out_m_ans and "ansible.builtin.reboot" in out_m_ans, "SL Micro Ansible playbook uses transactional-update and reboot task")

print("\n=== 7. LIFECYCLE BOUNDARIES: EOL & LTSS DETECTION ===")
rc_eol, out_eol, _ = run_cli("micro6.0", "CVE-2026-97876")
check(rc_eol == 0 and "End-of-Life" in out_eol, "Detects End-of-Life status on SL Micro 6.0")

rc_ltss, out_ltss, _ = run_cli("15sp6", "CVE-2026-97876")
check(rc_ltss == 0 and "LTSS" in out_ltss, "Detects LTSS lifecycle requirement on SLES 15 SP6")

print("\n=== 8. AIR-GAPPED / NETWORK OUTAGE RESILIENCE ===")
offline_env = os.environ.copy()
offline_env["http_proxy"] = "http://127.0.0.1:9"
offline_env["https_proxy"] = "http://127.0.0.1:9"
offline_proc = subprocess.run(
    [sys.executable, BIN, "15sp7", "CVE-2026-97876"],
    env=offline_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    universal_newlines=True,
    timeout=30,
)
check(offline_proc.returncode == 0 and "Traceback" not in offline_proc.stderr, "Gracefully degrades to local OVAL cache during total network outage")
check("EXECUTIVE TRIAGE SUMMARY" in offline_proc.stdout, "Still produces full triage summary when external APIs are unreachable")

print("\nALL EXTENDED STRESS & RESILIENCE TESTS PASSED.")
