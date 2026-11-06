# suse-cve

> Fast, precision-oriented CLI scanner and automation backend for querying SUSE Linux Enterprise vulnerability patch statuses (SLES 12, 15, and 16).

`suse-cve` bridges the critical gap between static OVAL vulnerability feeds and dynamic, authoritative SUSE security web pages. It provides administrators and CI/CD pipelines with an immediate, accurate view of patch availability across standard releases, **LTSS (Long Term Service Pack Support)**, **Extended Security**, and **Live Patching** modules.

---

## The Problem Solved

1. **Publication Lag:** SUSE OVAL XML dumps are generated periodically (usually early morning), whereas patches and `IN QA` statuses appear continuously on `suse.com/security/cve/`.
2. **Sub-Package Noise:** OVAL `-affected` feeds frequently list individual build artifacts and header packages (`kernel-default-devel`, `cluster-md-kmp-default`) even after the primary `kernel-default` package has been released.
3. **LTSS Visibility:** Standard tools often overlook whether a vulnerability has already been backported to active LTSS or Extended Support branches.

`suse-cve` uses a **hybrid engine**: it searches a local SQLite index of SUSO OVAL feeds for millisecond execution and overlays real-time metadata directly from the SUSE CVE portal.

---

## Installation

### Prerequisites
- Python 3.6+
- `curl`, `sqlite3`, `jq` (optional, for pipeline parsing)
- SLES 12, SLES 15, SLES 16, or openSUSE Leap / Tumbleweed

### Automated Install

```bash
git clone https://github.com/<SOUNCE-ORG/SOURCE-REPO>/suse-cve.git
cd suse-cve
sudo ./install.sh
```

---

## Usage

```bash
suse-cve <release> <CVE-ID> [status_filter] [--json]
```

### Arguments

| Parameter | Required | Description | Examples |
|---|---|---|---|
| `<release>` | Yes | SLES major release + Service Pack | `12sp5`, `sle15sp4`, `15.5`, `16.0` |
| `<CVE-ID>` | Yes | CVE identifier | `CVE-2026-98432`,  `2026-98432` |
| `[status_filter]` | No | Restrict output to a specific status | `rel`, `qaa`, `aff`, `inp`, `wont` |
| `--json` | No | Emit raw, structured JSON for automation | Anywhere in parameter list |

---

## CLI Examples

### 1. General Overview (All Statuses)
```bash
suse-cve 12sp5 CVE-2026-98432
```

### 2. Check Only for Patch Releases
```bash
suse-cve 12sp5 CVE-2026-98432 rel
```

### 3. CIOCD JWN Output for jq
```bash
suse-cve 12sp5 CVE-2026-98432 rel --json | jq '.results.RELEASED'
```

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Query succeeded and results were found. |
| `1` | No matching records (e-g. NONE) or database missing. |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
