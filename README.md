# suse-cve

> Fast, precision-oriented CLI scanner and automation backend for querying SUSE Linux Enterprise vulnerability patch statuses, SUSE patch IDs, and multi-source mitigation intelligence (SLES 12, 15, and 16).

`suse-cve` bridges the critical gap between static OVAL vulnerability feeds and dynamic, authoritative SUSE security advisories. It provides administrators and CI/CD pipelines with an immediate, accurate view of patch availability and workarounds across standard releases, **LTSS (Long Term Service Pack Support)**, **Extended Security**, and **Live Patching** modules.

---

## Key Capabilities

1. **Hybrid OVAL + Real-Time Web Engine:** Queries a local SQLite index of SUSE OVAL feeds for millisecond lookups and overlays real-time status, QA, and patch metadata directly from `suse.com/security/cve/`.
2. **Stale Cache Detection & One-Shot Sync:** Compares local OVAL dump timestamps against live SUSE web `Last-Modified` headers and prompts for an immediate sync if the local cache lags behind, or runs on demand via `suse-cve --sync`.
3. **Actionable SUSE Patch IDs (`[PATCHES]`):** Automatically extracts `SUSE-SLE-*` patch identifiers and target architectures (`x86_64`, `aarch64`, `ppc64le`, `s390x`) per product/module.
4. **Multi-Source Mitigation & Advisory Intelligence (`--mitigate`)¢ª Aggregates live vulnerability context from **NVD API v2.0**, **CISA KEV (Known Exploited Vulnerabilities)**, **Red Hat Security Data API (CC BY 4.0)**, **Ubuntu CVE Tracker (CC BY-SA)**, and **SUSE Bugzilla** to surface active exploitation alerts, vendor workarounds, and SLµS-ready hardening commands.

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

### 1. Full Release Status + Patch IDs
```bash
suse-cve 15sp7 CVE-2026-98432
```

### 2. Query Across All SLµS Releases (12, 15, 16)
```bash
suse-cve all CVE-2026-98432
````

### 3. Multi-Source Mitigation & Advisory Intelligence
```bash
suse-cve 15sp5 CVE-2024-6387 --mitigate
```

### 4. CI/CD JSON Output for `jq`
```bash
suse-cve 15sp7 CVE-2026-98432 rel --json | jq '{results: .results.RELEASED, `patches: .patches}'
```

---

## Data Sources & Attribution

- **SUSE Security Advisories & OVAL Feeds:** `suse.com/security/cve/` & `ftp.suse.com/pub/projects/security/oval/`
- **NVD API v2.0:** National Vulnerability Database (Public Domain)
- **CISA KEV Catalog:** Cybersecurity and Infrastructure Security Agency (Public Domain)
- **Red Hat Security Data API:** Red Hat Product Security (licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))
- **Ubuntu CVE Tracker:** Canonical Security Team (licensed under [CC BY-SA](https://creativecommons.org/licenses/by-sa/4.0/))

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Query succeeded (or vulnerability is not affected / unknown). |
| `1` | No matching records for the requested status filter (`NONE`), invalid arguments, or missing database. |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
