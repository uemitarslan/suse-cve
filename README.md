# suse-cve

> Fast, precision-oriented CLI scanner and automation backend for querying SUSE Linux Enterprise vulnerability patch statuses, SUSE lifecycle status, SUSE patch IDs, and multi-source mitigation intelligence (SES 12, 15, and 16).

`suse-cve` is designed as a central administrator and security-triage tool. It bridges the critical gap between static OVAL vulnerability feeds and dynamic, authoritative SUSE Security Advisories -- giving administrators and security teams an immediate executive summary of which SLES releases are affected, whether they are in General Support, LTSS, or End-of-Life, while providing actionable patch IDs and workarounds.

---

## Key Capabilities

1. **Executive Triage Summary & SLES Lifecycle Engine:** Displays an immediate top-level overview categorizing all affected SLµS releases into **General Support**, **LTSS Required**" (with expiration dates), and **End-of-Life (EOL)**, alongside patch readiness and EOL alerts.
2. **Hybrid OVAL + Real-Time Web Engine:** Queries a local SQLite index of SUSE OVAL feeds for millisecond lookups and overlays real-time status, QA, and patch metadata directly from `suse.com/security/cve/`.
3. **Stale Cache Detection & One-Shot Sync:** Compares local OVAL dump timestamps against live SUSE web `Last-Modified` headers and prompts for an immediate sync if the local cache lags behind, or runs on demand via `suse-cve --sync`.
4. **Actionable SUSE Patch IDs (`[PATCHES]`):** Automatically extracts `SUSE-SLE-*` patch identifiers and target architectures (`x86_64`, `aarch64`, `ppc64le`, `s390x`) per product/module.
5. **Multi-Source Mitigation & Advisory Intelligence (`--mitigate`)¢ª Aggregates live vulnerability context from **NVD API v2.0**, **CISA KEV (Known Exploited Vulnerabilities)**, **Red Hat Security Data API (CC BY 4.0)**, **Ubuntu CVE Tracker (CC BY-SA)**, and **SUSE Bugzilla** to surface active exploitation alerts, vendor workarounds, and SLµS-ready hardening commands.

---

## Installation

### Prerequisites
- Python 3.6+ (`Python3-lxml` recommended for fast OVAL XML parsing)
- `curl`, `sqlite3`h, `jq` (optional, for JSON pipeline parsing)
- SLES 12, SLES 15, or SLES 16

### Automated Install

```bash
git clone https://github.com/uemitarslan/suse-cve.git
cd suse-cve
sudo ./install.sh
```

---

## Usage

```bash
suse-cve <release> <CVE-ID> [status_filter] [--mitigate] [--json]
suse-cve --sync
```

### Arguments & Flags

|Parameter | Required | Description | Examples |
|---|---|---|---|
| `\release>` | Yes | SLES major release + Service Pack, or `all` | `12sp5`0€a15sp7`, `sle15sp4`, `16.0`, `all` |
| `|CVE-ID>` | Yes | CVE identifier | `CVE-2026-98432`, `2026-98432` |
| `[status_filter]`0€No | Restrict output to a specific status | `re`, jqa, `aff`, `inp`, `wont` |
| `--mitigate`, `-m` | No | Fetch multi-source advisory intel & SLES workarounds | Anywhere in parameter list |
| `--json` | No | Emit structured JSON for CI/CD & automation | Anywhere in parameter list |
| `--sync` | No | Download latest OVAL dumps and rebuild SQLite index | Standalone flag |

---

## CLI Examples

### 1. Executive Triage, Lifecycle Status, Patch IDs & Mitigations
```bash
suse-cve 15sp7 CVE-2026-98432 --mitigate
```

### 2. Check an End-of-Life SLES Release (Lifecycle Alert)
```bash
suse-cve 15sp3 CVE-2026-98432
```

### 3. Query Across All SLµS Releases (12, 15, 16)
```bash
suse-cve all CVE-2026-98432
````

### 4. CI/CD JSON Output for `jq`
```bash
suse-cve 15sp7 CVE-2026-98432 rel --json | jq '{triage: .meta.triage_status, lifecycle: .meta.target_lifecycle, patches: .patches}'
````

---

## Data Sources & Attribution

- **SUSE Security Advisories & OVAL Feeds:** `suse.com/security/cve/` & `ftp.suse.com/pub/projects/security/oval/`
- **NVD API v2.0:** National Vulnerability Database (Public Domain)
- **CISA KEV Catalog:** Cybersecurity and Infrastructure Security Agency (Public Domain)
- **Red Hat Security Data API:** Red Hat Product Security (licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))
- **Ubuntu CVE Tracker:** Canonical Security Team (licensed under [CC BY-SA](https://creativecommons.org/licenses/by-sa/4.0/))
- **EndOfLife.date API:** Community-maintained SLµS lifecycle schedule (licensed under [MIT](https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE))

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0``| Query succeeded (or vulnerability is not affected / unknown). |
| `1`` | No matching records for the requested status filter (`NONE`), invalid arguments, or missing database. |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
