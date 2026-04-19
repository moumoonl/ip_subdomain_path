# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Modular security scanning pipeline for subdomain collection, port scanning, service identification, and directory bruteforcing. Written in Python 3, shells out to Go-based security tools (ksubdomain, naabu, httpx, ffuf). UI is in Chinese.

## Commands

### Environment Setup
```bash
./setup.sh    # Check tool deps (Go, Python, ksubdomain, naabu, httpx, ffuf) + verify dict files
```

### Running Modules Individually
```bash
python module1_subdomain_collect.py --input domains.txt --output-dir results
python module1_subdomain_collect.py --input domains.txt --wildcard-threshold 200  # lower threshold
python module1_subdomain_collect.py --input domains.txt --passes 5               # more passes for max coverage
python module1_subdomain_collect.py --input domains.txt --no-verify              # skip DNS verify
python module2_port_scan_and_httpx.py --ips ips.txt --subdomains subdomains_valid.txt --output-dir results
python module3_directory_bruteforce.py --input http_services.txt --wordlist dict/gov-edu-med-paths-clean.txt --output-dir results
# Resume a specific batch's directory bruteforce only:
python module3_directory_bruteforce.py --input results/batch_001/http_services.txt --wordlist dict/gov-edu-med-paths-clean.txt --output-dir results/batch_001
```

### Full Pipeline
```bash
# From scratch: run module1 subdomain collection first
python full_pipeline.py --domains domains.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt

# Skip module1, use existing subdomains + IPs (most common)
python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt

# IPs only, no subdomain collection
python full_pipeline.py --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt --skip-module1

# Skip module2+module3 entirely (e.g. only run module1 subdomain collection)
python full_pipeline.py --domains domains.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt --skip-module2

# Tune batch size and concurrency
python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt --batch-size 50 --concurrency 10

# Deep scan with recursion
python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict/gov-edu-med-keywords-clean.txt --recursion-depth 2 --concurrency 10

# Force re-run (ignore all checkpoint caches)
python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt --force
```

## Architecture

Three independent modules orchestrated by `full_pipeline.py`:

```
full_pipeline.py  --orchestrates-->  [module1] -> module2 -> module3 (per batch)
```

- **`full_pipeline.py`** — Batch pipeline orchestrator. DNS-dedupes then merges all assets (subdomains first, IPs second), splits into batches (default 100/batch), runs module2→module3 per batch. When only one input type is provided (IPs only or subdomains only), DNS dedup is skipped. Appends results to top-level summary files after each batch. Checkpoint: skips batches where `ffuf_progress.txt` exists and is non-empty (`--force` to override).

- **`module1_subdomain_collect.py`** — Subdomain enumeration via `ksubdomain` with multi-pass scanning. Runs ksubdomain enum N times per domain (default 3, `--passes`), merges results with set union, then verifies with Python `socket.getaddrinfo` (TCP-fallback DNS, more reliable than ksubdomain's UDP-only verify). Uses `Popen`+SIGTERM for graceful termination (same pattern as naabu in module2). Custom DNS resolvers (`dict/resolvers.txt`, 7 domestic + 7 international) replace ksubdomain's default 2 resolvers to reduce rate-limiting. Lower bandwidth per pass (`-b 2m` vs original `-b 5m`) reduces packet loss; multi-pass compensates for missed subdomains. Wildcard/parked domain filtering: if a domain yields more subdomains than `--wildcard-threshold` (default 500), all results for that domain are discarded.

- **`module2_port_scan_and_httpx.py`** — Two-stage port scan via `naabu`: Stage 1 top-1000 probe (rate 2000, retries 2), Stage 2 full 1-65535 on alive hosts in `-stream` mode (rate 5000, no retries — fastest possible with CONNECT scan). Stage 2 is **optional** and skipped by default; requires `--allport` flag to enable. When Stage 2 is skipped, Stage 1 results are used directly as the final output. Results merged and deduped. Uses `Popen`+SIGTERM for graceful naabu termination (flushes output file on timeout). Then `httpx` probes for HTTP services with title/status/tech. DNS dedup: domains resolving to IPs already in the IP list are dropped. When called from the pipeline, DNS dedup is already done upstream; when called standalone, it dedupes internally in `merge_targets()`. Subdomains are placed before IPs in the merged target list so naabu scans subdomains first. When only one input type is provided, DNS dedup is skipped.

- **`module3_directory_bruteforce.py`** — Directory bruteforce via `ffuf` with multi-target concurrency (`ThreadPoolExecutor`). False-positive filtering: (status, content_length) pairs appearing in >70% of results are discarded (threshold hardcoded at `filter_false_positives()` line 34). After ffuf completes, runs `httpx` on all sensitive URLs to extract page titles, generating `sensitive_urls_title.txt` (`URL [title]` format; graceful skip if httpx unavailable). Checkpoint: tracks completed URLs in `ffuf_progress.txt`.

- **`utils.py`** — Shared utilities: colored terminal output (`Colors`, `print_info/success/warning/high_risk`), `run_command()` with timeout and real-time output file monitoring via background thread, `format_time_remaining()`.

## Key Design Patterns

- **Checkpoint/resume**: Module2 checks for existing `all_ports.txt`/`http_services.txt`; module3 uses `ffuf_progress.txt`; full_pipeline checks per-batch `ffuf_progress.txt`. All respect `--force`. Module1 has **no** checkpoint — it always reruns from scratch.
- **ksubdomain multi-pass**: Module1 runs ksubdomain enum N times per domain (default 3 passes via `--passes`) and merges results. This compensates for UDP DNS packet loss — each pass misses different subdomains, so the union is significantly more complete than a single pass. Dynamic timeout per pass: `max(300, min(dict_entries×6, 3600))` (min 5min, max 1h).
- **ksubdomain graceful termination**: `run_ksubdomain()` uses `Popen` instead of `subprocess.run`. On timeout, sends SIGTERM first, waits 10s, then SIGKILL. Same pattern as `run_naabu()` in module2.
- **Python DNS verify**: After multi-pass enum, `verify_subdomains_dns()` uses `socket.getaddrinfo` (with TCP fallback, 3 retries per subdomain) to remove false positives. Much more reliable than ksubdomain's UDP-only verify. Can be skipped with `--no-verify`.
- **Custom DNS resolvers**: `dict/resolvers.txt` contains 14 DNS servers (7 domestic: Alibaba, 114, Tencent, Baidu; 7 international: Cloudflare, Google, Quad9, OpenDNS). Replaces ksubdomain's default of only 2 resolvers (`1.1.1.1` + `8.8.8.8`), drastically reducing rate-limiting and packet loss.
- **`--force` propagation**: When `full_pipeline.py --force` is used, `--force` is passed through to module2 and module3 subprocess calls. Similarly, `--allport` is passed through to module2 to enable Stage 2 full-port scanning.
- **Dynamic timeouts**: Module1 per-pass = `max(300, min(dict_entries×6, 3600))` (min 5min, max 1h); Stage 1 (top-1000) = `max(300, min(targets×90, 7200))` (min 5min, max 2h); Stage 2 (full ports on alive hosts) = `max(600, min(alive×600, 86400))` (min 10min, max 24h); httpx = `max(300, min(port_count, 7200))`. Never hardcode timeouts when modifying scan logic.
- **naabu graceful termination**: `run_naabu()` uses `Popen` instead of `subprocess.run`. On timeout, sends SIGTERM first (naabu catches it and flushes `-o` output file), waits 10s, then SIGKILL. This prevents the old bug where SIGKILL caused empty output files.
- **naabu `-stream` for Stage 2**: Full 65535-port scan on alive hosts uses `-stream` mode (disables retries, resume, shuffling) with rate 5000 for maximum speed. Stage 1 already provides the reliable baseline; Stage 2 is supplementary. Stage 2 is **optional** — skipped by default, enabled with `--allport` flag on module2 or full_pipeline.
- **Batch processing**: `full_pipeline.py` splits merged assets into batches to limit naabu scope. Each batch gets its own subdirectory under `results/batch_XXX/`.
- **Real-time output**: Sensitive URLs and HTTP services are appended to top-level summary files after each batch completes. Title file (`sensitive_urls_title.txt`) is also appended per-batch; a reconciliation step at the end of the pipeline regenerates the top-level title file from `sensitive_urls.txt` if it's incomplete (e.g., due to a module3 crash that prevented `generate_title_file()` from running).
- **DNS dedup** (`merge_targets` in module2, `dns_dedupe` in full_pipeline): Domains that resolve to IPs already in the input IP list are dropped to avoid redundant scanning. Only runs when both IPs and subdomains are provided; skipped when only one input type is present. Merged output places subdomains before IPs so naabu scans subdomains first.
- **High-value target detection** (module2): httpx output lines are scanned for keywords (`login`, `admin`, `dashboard`, `panel`, `管理`, `后台`, etc.) and flagged immediately in red.
- **False-positive filter** (module3 `filter_false_positives()`): `(status, content_length)` pairs appearing in >70% of ffuf results per target are discarded as WAF/wildcard noise. Threshold is hardcoded at line 34 — edit directly to tune.
- **Non-HTTP service inference** (module2 `common_services` dict): Ports like 22→ssh, 3306→mysql, 6379→redis etc. are mapped to service names. Endpoints not matched by httpx are labeled with the inferred service name.
- **ffuf match/sensitive codes**: ffuf matches `-mc 200,204,301,302,307,403,401,500`; `extract_sensitive_urls()` then filters to status codes `[200,204,401,403,500]` for the final output (redirects excluded).
- **Title file generation** (module3 `generate_title_file()`): After ffuf scan completes, reads all URLs from `sensitive_urls.txt`, runs httpx in JSON mode (`-json -silent`) to batch-probe titles, and writes `sensitive_urls_title.txt` in `URL [title]` format (URL only if title unavailable). Graceful skip if httpx not installed or times out (600s). The pipeline appends batch-level title files to top-level, then runs a reconciliation step: if top-level `sensitive_urls_title.txt` has fewer lines than `sensitive_urls.txt`, it regenerates from scratch using `generate_title_file_from_urls()`.

### Testing
```bash
python test_ksubdomain_consistency.py --input test_domains.txt --runs 3           # 3 runs, compare Jaccard similarity
python test_ksubdomain_consistency.py --input test_domains.txt --runs 3 --passes 1  # single-pass comparison
```

### Monitoring Long Runs

```bash
tail -f results/sensitive_urls.txt          # live sensitive URL feed
wc -l results/http_services.txt             # HTTP service count so far
ls results/batch_*/ffuf_progress.txt 2>/dev/null | wc -l  # completed batches
```

Use `screen` or `tmux` for multi-hour runs.

## External Tool Dependencies

All must be in PATH (install via `go install`, default lands in `$HOME/go/bin`):
- `ksubdomain` — subdomain bruteforce (`github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest`)
- `naabu` — port scanning (`github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`)
- `httpx` — HTTP service detection (`github.com/projectdiscovery/httpx/cmd/httpx@latest`)
- `ffuf` — directory bruteforce (`github.com/ffuf/ffuf/v2@latest`)

## Dictionary Files (`dict/`)

- `gov-edu-med-paths-clean.txt` — smallest, fastest (paths)
- `gov-edu-med-dict-clean.txt` — medium (dict)
- `gov-edu-med-keywords-clean.txt` — largest, deepest (keywords)
- `oneforall_subnames.txt` — subdomain enumeration only (module1 default)
- `resolvers.txt` — custom DNS resolvers for ksubdomain (7 domestic + 7 international)

## Output Structure

```
results/
├── subdomains_valid.txt          # module1 output
├── batch_001/                    # per-batch results
│   ├── targets_batch.txt         # raw asset list for this batch
│   ├── ips_batch.txt             # IP-only targets split from batch
│   ├── domains_batch.txt         # domain-only targets split from batch
│   ├── targets_merged.txt        # after module2 internal DNS dedup (standalone mode; subdomains first, IPs second)
│   ├── all_ports_stage1.txt      # naabu stage1: top-1000 results (host:port)
│   ├── all_ports_stage2.txt      # naabu stage2: full-port results on alive hosts (requires --allport)
│   ├── alive_hosts.txt           # hosts confirmed alive by stage1
│   ├── all_ports.txt             # merged deduped results (host:port; stage1 only if --allport not set)
│   ├── http_services.txt         # httpx output: URL [status] [title] [tech]
│   ├── non_http_services.txt     # non-HTTP ports with service name inferred
│   ├── sensitive_urls.txt        # ffuf findings after false-positive filter
│   ├── sensitive_urls_title.txt  # sensitive URLs with page titles (URL [title] format, via httpx)
│   └── ffuf_progress.txt         # checkpoint: one completed URL per line
├── http_services.txt             # aggregated across batches
├── sensitive_urls.txt            # aggregated across batches
├── sensitive_urls_title.txt      # aggregated across batches (with reconciliation)
└── non_http_services.txt         # aggregated across batches
```
