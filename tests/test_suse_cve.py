import time
#!/usr/bin/env python3
import json
import os
import subprocess
import sys

BIN = os.path.abspath("bin/suse-cve")

def run_cli(*args):
    time.sleep(0.2)
    proc = subprocess.run(
        [sys.executable, BIN, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=90,
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
    timeout=90,
)
check(offline_proc.returncode == 0 and "Traceback" not in offline_proc.stderr, "Gracefully degrades to local OVAL cache during total network outage")
check("EXECUTIVE TRIAGE SUMMARY" in offline_proc.stdout, "Still produces full triage summary when external APIs are unreachable")

print("\nALL EXTENDED STRESS & RESILIENCE TESTS PASSED.")

print("\n=== 9. MODULAR BATCH SCANNING (COMMA, --FILE, STDIN, --JSON) ===")
rc_b1, out_b1, err_b1 = run_cli("15sp7", "CVE-2026-97876,CVE-2026-98432")
check(rc_b1 == 0 and "[EXECUTIVE BATCH TRIAGE SUMMARY]" in out_b1, "Batch scan runs cleanly on comma-separated CVE list")
check("CVE-2026-97876" in out_b1 and "CVE-2026-98432" in out_b1, "Batch summary table includes all requested CVEs")

rc_b2, out_b2, _ = run_cli("15sp7", "CVE-2026-97876,CVE-2026-98432", "--json")
bdata = json.loads(out_b2)
check(rc_b2 == 0 and bdata.get("batch") is True and bdata.get("summary", {}).get("total") == 2, "Batch --json emits structured batch summary and results")
check(len(bdata.get("results", [])) == 2, "Batch --json preserves full per-CVE triage objects in results")

tmp_cve_file = "/tmp/test_suse_cve_batch.txt"
with open(tmp_cve_file, "w", encoding="utf-8") as fh:
    fh.write("# Comment line\n\ncve-2026-97876.\nCVE-2026-97876\nCVE-2026-98432\n")
try:
    rc_bf, out_bf, _ = run_cli("12sp5", "--file", tmp_cve_file, "--json")
    bfdata = json.loads(out_bf)
    check(rc_bf == 0 and bfdata.get("summary", {}).get("total") == 2 and bfdata.get("summary", {}).get("not_affected") >= 1 and (bfdata.get("summary", {}).get("not_affected", 0) + bfdata.get("summary", {}).get("affected_or_pending", 0) + bfdata.get("summary", {}).get("patched", 0)) == 2, "--file deduplicates CVEs, ignores comments/blank lines, and classifies NOT AFFECTED")
finally:
    if os.path.exists(tmp_cve_file):
        os.remove(tmp_cve_file)

stdin_proc = subprocess.run(
    [sys.executable, BIN, "--file", "-", "--json"],
    input="CVE-2026-97876\nCVE-2026-98432\n",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    universal_newlines=True,
    timeout=90,
)
sdata = json.loads(stdin_proc.stdout)
check(stdin_proc.returncode == 0 and sdata.get("release") == "all" and sdata.get("summary", {}).get("total") == 2, "Supports reading CVEs from stdin (-f -) with implicit 'all' release")

rc_bad_b, _, err_bad_b = run_cli("15sp7", "CVE-2026-97876,INVALID-CVE")
check(rc_bad_b != 0 and "Invalid CVE identifier" in err_bad_b, "Rejects batch input containing malformed CVE identifiers")

rc_fo, out_fo, _ = run_cli("12sp5", "CVE-2026-97876,CVE-2026-98432", "--only-open", "--json")
fodata = json.loads(out_fo)
check(
    rc_fo == 0
    and fodata.get("batch_filters", {}).get("only_open") is True
    and fodata.get("summary", {}).get("displayed") == len(fodata.get("rows", []))
    and all("NOT AFFECTED" not in r["status"].upper() and not r["status"].upper().startswith("PATCHED") for r in fodata.get("rows", [])),
    "--only-open filters out NOT AFFECTED / PATCHED rows while preserving summary totals"
)

rc_fk, out_fk, _ = run_cli("15sp7", "CVE-2026-97876,CVE-2026-98432", "--only-kev", "--json")
fkdata = json.loads(out_fk)
check(
    rc_fk == 0
    and fkdata.get("batch_filters", {}).get("only_kev") is True
    and fkdata.get("summary", {}).get("displayed") == len(fkdata.get("rows", []))
    and all("[KEV!]" in r["severity"] for r in fkdata.get("rows", [])),
    "--only-kev retains only CISA KEV-listed vulnerabilities"
)

import time
for _attempt in range(3):
    rc_pid, out_pid, _ = run_cli("15sp7", "CVE-2026-97876,CVE-2026-98432", "--json")
    if "SUSE-SLE-" in out_pid:
        break
    time.sleep(1.0)
piddata = json.loads(out_pid)
act_val = next((r["action"] for r in piddata.get("rows", []) if r.get("cve") == "CVE-2026-98432"), "")
check("SUSE-SLE-" in act_val and "SUSE Linux Enterprise" not in act_val, "Batch action column renders clean SUSE-SLE-* patch IDs instead of product names")

rc_t1, out_t1, _ = run_cli("15sp7", "CVE-2026-98432", "--table")
check(rc_t1 == 0 and "[EXECUTIVE BATCH TRIAGE SUMMARY]" in out_t1 and "PATCHES / ACTION" in out_t1 and "[MITIGATION & MULTI-SOURCE" not in out_t1, "--table renders compact 1-row triage table for a single CVE")

rc_s1, out_s1, _ = run_cli("15sp7", "CVE-2026-98432")
check(rc_s1 == 0 and "PATCHES / ACTION" in out_s1 and "[EXECUTIVE TRIAGE SUMMARY]" in out_s1, "Default single-CVE output includes compact 1-row triage header table above details")

rc_unp, out_unp, _ = run_cli("15sp7", "CVE-2026-0394,CVE-2026-0398")
check(rc_unp == 0 and "[ACTION REQUIRED — OPEN / UNPATCHED CVEs (1)]" in out_unp and "suse-cve 15sp7 CVE-2026-0394 --mitigate" in out_unp, "Batch output displays actionable --mitigate command hints for UNPATCHED CVEs")

for _attempt in range(3):
    rc_p12, out_p12, _ = run_cli("12sp5", "CVE-2026-0394,CVE-2026-98432")
    if "SUSE-SLE-SERVER-12-SP5" in out_p12:
        break
    time.sleep(1.0)
check(rc_p12 == 0 and "suse-cve 12sp5 CVE-2026-0394 --mitigate" in out_p12 and "suse-cve 12sp5 CVE-2026-98432 --remediate" in out_p12, "Footer chooses --mitigate vs --remediate for PARTIALLY PATCHED based on patch availability")

check("suse-cve 12sp5 CVE-2026-0394 --mitigate (No Patch | SUSE:" in out_p12 and "Patch Pending" not in out_p12, "Action column provides full copy-pasteable --mitigate command when target patch is absent")

check("[STATUS GUIDE — RISK & NEXT STEPS]" in out_p12 and "PARTIALLY PATCHED :" in out_p12, "Batch output includes management-friendly status guide explaining risk and next steps")

rc_s156, out_s156, _ = run_cli("15sp6", "CVE-2026-0394")
check("suse-cve 15sp6 CVE-2026-0394 --mitigate" in out_s156, "Single-CVE header table uses exact target release in --mitigate command")
rc_dup, out_dup, _ = run_cli("15sp6", "suse-cve", "15sp6", "CVE-2026-98432", "--remediate")
check(rc_dup == 0 and "CVE-2026-98432" in out_dup, "Tolerates accidental duplicate 'suse-cve <target>' prefix on paste")

check("I've read https://" not in out_s156, "Filters out Bugzilla discussion chatter from workaround output")
rc_rem6, out_rem6, _ = run_cli("15sp6", "CVE-2026-98432", "--remediate")
rem_line = next((ln for ln in out_rem6.splitlines() if "Explicit patch IDs:" in ln), "")
check("SUSE-SLE-Product-SLES-15-SP6" in rem_line and rem_line.find("Product-SLES") < (rem_line.find("Live-Patching") if "Live-Patching" in rem_line else 9999), "Prioritizes standard SLES product patches before Live-Patching in --remediate")
rc_res6, out_res6, _ = run_cli("15sp6", "CVE-2026-0438", "--table")
check("No Target RPM Yet | SUSE: Resolved Upstream" in out_res6, "Clarifies 'SUSE: Resolved Upstream' when target release RPM is not yet published")

rc_brem, out_brem, _ = run_cli("12sp5", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--remediate")
check(rc_brem == 0 and "[BATCH REMEDIATION (VENDOR PATCHES)]" in out_brem and "zypper patch --cve=CVE-2026-98432" in out_brem and "Compensating Workarounds" not in out_brem, "Batch mode honors --remediate and strictly separates patches from workarounds")
rc_bmit, out_bmit, _ = run_cli("12sp5", "CVE-2026-0394,CVE-2026-0438", "--mitigate")
check(rc_bmit == 0 and "[BATCH MITIGATIONS (COMPENSATING WORKAROUNDS)]" in out_bmit and "Recommended SLES Workarounds" in out_bmit, "Batch mode honors --mitigate and renders per-CVE workaround blocks below summary table")


print("\n=== 10. BATCH IAC GENERATION (--ANSIBLE-CONFIG & --SALT-CONFIG) ===")
rc_bans, out_bans, _ = run_cli("15sp6", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--ansible-config")
check(rc_bans == 0 and "---" in out_bans and "\n    - name: Refresh zypper" in out_bans and "\n    - name: \"[CVE-2026-0438]" in out_bans and "zypper --non-interactive patch --cve=CVE-2026-98432" in out_bans and "ansible.posix.sysctl:" in out_bans and "ansible.builtin.reboot:" in out_bans, "Batch --ansible-config generates valid 4-space indented YAML playbook combining zypper patch, sysctl workarounds, and single reboot")
rc_bsalt, out_bsalt, _ = run_cli("15sp6", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--salt-config")
check(rc_bsalt == 0 and "cve_batch_zypper_patch:" in out_bsalt and "sysctl.present:" in out_bsalt and "cve_batch_reboot_notice:" in out_bsalt, "Batch --salt-config generates unified multi-CVE Salt state with deduplicated patch & sysctl blocks")
rc_bmit_ans, out_bmit_ans, _ = run_cli("15sp6", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--ansible-config", "--mitigate")
check(rc_bmit_ans == 0 and "zypper --non-interactive patch" not in out_bmit_ans and "ansible.posix.sysctl:" in out_bmit_ans, "Batch --ansible-config --mitigate forces compensating workarounds instead of zypper patch")

print("\nALL 10 TEST SUITES (INCLUDING BATCH IAC GENERATOR) PASSED.")

print("\n=== 11. CSV & MARKDOWN MANAGEMENT REPORTING (--CSV & --MARKDOWN) ===")
rc_csv, out_csv, _ = run_cli("15sp6", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--csv")
import csv as _csv, io as _io
csv_rows = list(_csv.reader(_io.StringIO(out_csv)))
check(
    rc_csv == 0
    and len(csv_rows) == 4
    and csv_rows[0] == ["CVE", "Target_Release", "Status", "Status_Detail", "Severity", "CVSS_Max", "CISA_KEV", "Lifecycle", "Recommended_Action", "CLI_Next_Step", "Mitigation_Sources", "Mitigations_Summary", "Verify_URLs", "Rollback_Commands"]
    and csv_rows[1][0] == "CVE-2026-0394"
    and csv_rows[1][5] == "5.3"
    and csv_rows[3][0] == "CVE-2026-98432"
    and csv_rows[3][5] in ("9.8", "N/A")
    and "SUSE-SLE-" in csv_rows[3][8],
    "Batch --csv emits valid RFC-4180 CSV with CVSS scores, lifecycle, and actionable CLI next steps",
)

rc_md, out_md, _ = run_cli("15sp6", "CVE-2026-0394,CVE-2026-0438,CVE-2026-98432", "--markdown")
check(
    rc_md == 0
    and "# SUSE Security Vulnerability Triage Report (`15sp6`)" in out_md
    and "## Executive Summary" in out_md
    and "## Vulnerability Triage Matrix" in out_md
    and "| `CVE-2026-98432` | PARTIALLY PATCHED |" in out_md
    and "| 5.3 |" in out_md
    and r"No Target RPM Yet \| SUSE:" in out_md
    and "## Action Required — Open / Unpatched CVEs (3)" in out_md
    and "## Audit & Compliance Status Guide" in out_md,
    "Batch --markdown generates executive audit report with KPI summary, pipe-escaped table, and action commands",
)

rc_md_single, out_md_single, _ = run_cli("12sp5", "CVE-2026-97876", "--md")
check(
    rc_md_single == 0
    and "| `CVE-2026-97876` | NOT AFFECTED / NO OPEN VULNERABILITY |" in out_md_single
    and "## Action Required" not in out_md_single,
    "Single-CVE --md alias produces clean compliant report without false action items for NOT AFFECTED",
)

print("\n=== 12. MULTI-PACKAGE SOURCE ISOLATION & LIFECYCLE AGGREGATION ===")
rc_mp, out_mp, _ = run_cli("15sp6", "CVE-2026-0394", "--json")
data_mp = json.loads(out_mp)
meta_mp = data_mp.get("meta", {})
aff_15sp6 = data_mp.get("results", {}).get("AFFECTED", {}).get("SUSE Linux Enterprise Server 15 SP6", [])
na_15sp6 = data_mp.get("results", {}).get("NOT AFFECTED", {}).get("SUSE Linux Enterprise Server 15 SP6", [])
check(
    rc_mp == 0
    and "SLES 15 SP7" in meta_mp.get("affected_sles_releases", [])
    and "SLES 15 SP6" in meta_mp.get("affected_sles_releases", [])
    and "SLES 15 SP7" not in meta_mp.get("not_affected_releases", [])
    and "SLES 15 SP1-SP5" not in meta_mp.get("not_affected_releases", []),
    "Multi-package CVE classifies affected SLES 15 SP1..SP7 accurately without false NOT AFFECTED masking",
)
check(
    "dovecot23" in aff_15sp6
    and "dovecot" not in aff_15sp6
    and "dovecot" in na_15sp6,
    "Separates unaffected source package (dovecot) from affected binary package (dovecot23) in [AFFECTED] vs [NOT AFFECTED]",
)

rc_mp12, out_mp12, _ = run_cli("12sp5", "CVE-2026-0394", "--json")
data_mp12 = json.loads(out_mp12)
check(
    rc_mp12 == 0
    and data_mp12.get("meta", {}).get("patched_releases") == []
    and "RELEASED" not in data_mp12.get("results", {})
    and "dovecot" in data_mp12.get("results", {}).get("NOT AFFECTED", {}).get("SUSE Linux Enterprise Server for SAP Applications 12 SP5", []),
    "Prevents false OVAL RELEASED status on SLES 12 SP5 SAP when web advisory reports Not affected",
)



print("\n=== 13. CRISIS MITIGATION ATTRIBUTION, ROLLBACKS & MULTI-FORMAT PARITY ===")
rc_ccli, out_ccli, _ = run_cli("15sp7", "CVE-2026-98432", "--mitigate")
check(rc_ccli == 0 and "[Due to Red Hat (RHSB-2026-016)]" in out_ccli and "Source / Verify: https://access.redhat.com/security/vulnerabilities/RHSB-2026-016" in out_ccli and "Rollback (post-patch): rm -f /etc/nftables.d/cve_2026_98432.nft" in out_ccli, "CLI --mitigate displays source attribution, Verify URLs, and post-patch rollback commands")

rc_cans, out_cans, _ = run_cli("15sp7", "CVE-2026-98432,CVE-2026-97876", "--mitigate", "--ansible")
check(rc_cans == 0 and "/etc/nftables.d/cve_2026_98432.nft" in out_cans and "nft --file /etc/nftables.d/cve_2026_98432.nft" in out_cans and "/boot/grub2/grub.cfg" in out_cans and "mode: '0600'" in out_cans and "nft -f - <<'EOF'" not in out_cans, "Ansible --mitigate uses native nftables/GRUB2 modules with source attribution instead of raw shell heredocs")

rc_csalt, out_csalt, _ = run_cli("15sp7", "CVE-2026-98432,CVE-2026-97876", "--mitigate", "--salt")
check(rc_csalt == 0 and "/etc/nftables.d/cve_2026_98432.nft" in out_csalt and "nft --file /etc/nftables.d/cve_2026_98432.nft" in out_csalt and "/boot/grub2/grub.cfg" in out_csalt and "mode: '0600'" in out_csalt and "nft -f - <<'EOF'" not in out_csalt, "SaltStack --mitigate uses native file.managed/cmd.run states with source attribution instead of raw shell heredocs")

rc_cmd, out_cmd, _ = run_cli("15sp7", "CVE-2026-98432,CVE-2026-97876", "--markdown")
check(rc_cmd == 0 and "## Compensating Mitigations & Hardening Details" in out_cmd and "**[Due to Red Hat (RHSB-2026-016)]**" in out_cmd and "**Rollback (post-patch):**" in out_cmd, "Markdown report embeds full source-attributed compensating mitigations and post-patch rollbacks")

rc_ccsv, out_ccsv, _ = run_cli("15sp7", "CVE-2026-98432", "--csv")
check(rc_ccsv == 0 and "Mitigation_Sources,Mitigations_Summary,Verify_URLs,Rollback_Commands" in out_ccsv and "Red Hat (RHSB-2026-016)" in out_ccsv, "CSV export includes Mitigation_Sources, Verify_URLs, and Rollback_Commands audit columns")

rc_cjson, out_cjson, _ = run_cli("15sp7", "CVE-2026-98432", "--json")
j_data = json.loads(out_cjson) if rc_cjson == 0 else {}
j_sugs = (j_data.get("mitigation") or {}).get("suggestions") or []
check(rc_cjson == 0 and any(s.get("source_attribution") and s.get("source_urls") and s.get("rollback") for s in j_sugs), "JSON output includes structured source_attribution, source_urls, and rollback fields on suggestions")

print("\nALL 13 TEST SUITES PASSED.")
