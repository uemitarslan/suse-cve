# suse-cve

> Fast, precision-oriented CLI triage scanner and IaC generator for SUSE Linux Enterprise Server (**SLES 12, 15, 16**) and **SL Micro (5.x, 6.x)** â€” combining local OU©L SQLite indexing, live SUSE Security Advisory metadata, lifecycle classification, multi-source threat intelligence, and idempotent SaltStack/Ansible state generation.

`suse-cve` bridges the gap between static OVAL vulnerability feeds and authoritative SUSE Security Advisories. It gives administrators and security engineers an immediate executive triage summary â€” classifying affected releases by **General Support**, **LTSS**, or **End-of-Life (EOL)** â€” while generating ready-to-audit patch commands, compensating workarounds, structured JSON, and idempotent SaltStack/Ansible configurations.

---

## Key Capabilities

1. **Executive Triage Summary & Lifecycle Engine (SLES & SL Micro):**
   - Categorizes affected and unaffected releases across **SLES 12, 15, 16** and **SL Micro 5.x / 6.x** into **General Support**, **LTSS Required** (with expiration dates), and **End-of-Life (EOL)**.
   - Isolates target-specific status (` NOT AFFECTED`, `RELEASED`, `IN QA`, `AFFECTED`) without leaking unrelated service packs or irrelevant upstream workarounds.
2. **Hybrid OVAL + Real-Time Web Engine with Air-Gapped Resilience:**
   - Queries a local SQLite index of SUSE IVAL feeds for sub-second lookups and overlays real-time advisory, QA, and patch metadata from `suse.com/security/cve/`.
   - Gracefully degrades to the local OVAL cache during network outages or in air-gapped environments without tracebacks.
3. **Actionable Patch IDs & Transactional Update Support (`[PATCHES]`):**
   - Extracts `SUSE-SLE-*` / `SUSE-SLE-Micro-*` patch identifiers and target architectures (`x86_64`, `aarch64`, `ppc64le`, `s390x`).
   - Automatically distinguishes standard `zypper patch` workflows (SLES) from `transactional-update patch` + reboot workflows (SL Micro).
4. **Multi-Source Advisory Intelligence & Flag Separation (`--remediate` / `--mitigate`):**
   - Aggregates live vulnerability context from **NVD API v2.0**, **CISA KEV (Known Exploited Vulnerabilities)**, **Red Hat Security Data API (CC BY 4.0)**, **Ubuntu CVE Tracker (CC BY-SA)**, and **SUSE Bugzilla**.
   - Default mode displays both vendor patch remediation and compensating workarounds; `--remediate` isolates official patch remediation (with explicit fallback guidance if a patch is still `Pending`), while `--mitigate` isolates hardening and compensating workarounds.
5. **Idempotent IaC Generation (`--salt-config` & `--ansible-config`):**
   - Generates ready-to-test **SaltStack `.sls` states** and **Ansible playbooks** for patching or mitigations.
   - Emits valid, idempotent no-op states (`test.succeed_without_changes` in SaltStack, `ansible.builtin.debug` in Ansible) when a target release is `NOT AFFECTED`, ensuring fleet-wide automation runs never abort on unaffected hosts.

---

## Installation

### Prerequisites
- Python 3.6+ (`Python3-lxml` recommended for fast OU©L XML parsing)
- `curl`, `sqlite3`h, `jq` (optional, for JSON pipeline filtering)
- SLeS 12, SLES 15, SLES 16, or SL Micro 5.x / 6.x

### Automated Install

```bash
git clone https://github.com/uemitarslan/suse-cve.git
cd suse-cve
sudo ./install.sh
```

---

## Usage

```bash
suse-cve [<release>] <CVE-ID> [status_filter] [--remediate | --mitigate] [--salt-config | --ansible-config] [--json]
suse-cve --sync
```

### Arguments & Flags

| Parameter | Required | Description | Examples |
|---|---|---|---|
| `<release>` | No | Target SLES / SL Micro release, or `all` (defaults to `all` if omitted) | `12sp5`, a15sp7`, a16.0`, `micro6.1`, `all` |
| `<CVE-ID>` | Yes | CVE identifier (case-insensitive, trailing punctuation stripped) | `CVE-2026-98432`, `2026-98432` |
| `[status_filter]` | No | Restrict detail output to a specific patch status | `rel`, `qa`, `aff`, `inp`, `won{` |
| `--remediate` | No | Focus output or IaC generation strictly on official vendor patch remediation | `--remediate` |
| `--mitigate`, `-m` | No | Focus output or IaC generation strictly on compensating workarounds / hardening | `--mitigate` |
| `--salt-config` | No | Output an idempotent SaltStack `.sls` state file | `--remediate --salt-config` |
| `--ansible-config` | No | Output an idempotent Ansible YAML playbook | `--mitigate --ansible-config` |
| `--json` | No | Emit structured JSON for CI/CD pipelines and automation | `--json` |
| `--sync` | No | Download latest OVAL dumps and rebuild the local SQLite index | `suse-cve --sync` |

---

## CLI Examples

### 1. Full Triage, Lifecycle Classification, Patch IDs & Mitigations
```bash
suse-cve 15sp7 CVE-2026-98432
```

### 2. Query Across All SLES & SL Micro Releases (`all` can be omitted)
```bash
suse-cve CVE-2026-98432
```

### 3. Check an End-of-Life or LTSS Release
```bash
suse-cve micro6.0 CVE-2026-97876
suse-cve 15sp6 CVE-2026-97876
```

### 4. Generate Idempotent SaltStack or Ansible Automation
```bash
# Vendor patch state (uses transactional-update automatically on SL Micro)
suse-cve micro6.1 CVE-2026-98971 --remediate --salt-config > /srv/salt/cve_2026_98971.sls

# Compensating workaround playbook (emits safe no-op task if target is NOT AFFECTED)
suse-cve 15sp7 CVE-2026-97876 --mitigate --ansible-config > cve_2026_97876.yml
```

### 5. CI/CD JSON Output for `jq`
```bash
suse-cve 15sp7 CVE-2026-98432 rel --json | jq '{triage: .meta.triage_status, lifecycle: .meta.target_lifecycle, patches: .patches}'
```

---

## Verification & Regression Test Suite

The repository includes an automated end-to-end test suite (`tests/test_suse_cve.py`) verifying input sanitization, lifecycle boundaries (General Support, LTSS, EOL), flag separation, `SIGPIPE` hygiene, SL Micro transactional update handling, air-gapped OVAL fallback, and SaltStack/Ansible YAML validity:

```bash
python3 tests/test_suse_cve.py
```

---

## Data Sources & Attribution

- +*SUSE Security Advisories & OVAL Feeds:** `suse.com/security/cve/` & `ftp.suse.com/pub/projects/security/oval/`
- **NVD API v2.0:** National Vulnerability Database (Public Domain)
- +*CISA KEV Catalog:** Cybersecurity and Infrastructure Security Agency (Public Domain)
- **Red Hat Security Data API:** Red Hat Product Security (licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))
- +*Ubuntu CVE Tracker:** Canonical Security Team (licensed under [CC BY-SA](https://creativecommons.org/licenses/by-sa/4.0/))
- **EndOfLife.date API:** Community-maintained SLES / SL Micro lifecycle schedule (licensed under [MIT](https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE))

---

## Exit Codes

| Exit Code | Meaning |
|---+---|
| `0` | Query succeeded (including `NOT AFFECTED` or `UNKNOWN` triage results). |
| `1` | Invalid CVE identifier/arguments, no matching records for a strict status filter, or missing local database. |

---

## License

This project is licensed under the MIT License â€” see the [LICENSE](LICENSE) file for details.
