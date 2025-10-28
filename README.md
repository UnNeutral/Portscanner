# Advanced Port Scanner in Python

A multi-threaded port scanner in Python for quickly identifying open TCP and UDP ports. Supports configurable port ranges, incremental CSV export, banner-grabbing heuristics and optional TLS probing.

> ⚠️ **Ethics:** Only scan systems you own or have explicit permission to test. Use `--yes` to confirm permission.

## Key features
- Multi-threaded scanning for speed (configurable worker count)
- TCP & UDP probes with simple banner heuristics
- Incremental CSV output (file opened at start and flushed per-row)
- Optional TLS probing for HTTPS-like ports
- Rate limiting, timeout control, and verbose logging
- Graceful shutdown on Ctrl+C (partial results preserved)

## Requirements
- Python 3.9+ (3.10 recommended)
- No external pip packages required
- Run with appropriate privileges if needed (e.g., `sudo` on some OSes)

## Quick flags
- `--udp` — enable UDP scanning  
- `--tls` — force TLS probe for TCP ports  
- `--threads` / `-t` — worker count (default 50)  
- `--timeout` — socket timeout (seconds)  
- `--rate` — per-worker delay (seconds)  
- `--output` / `-o` — `.csv` or `.json` output file  
- `--yes` — acknowledge you have permission to scan (required)  
- `--verbose` / `-v` — enable debug logging

## Notes on behavior
- **CSV handling:** When `--output` ends with `.csv`, the script creates the CSV at start (header written). Rows are appended and flushed as results arrive, so interrupting the scan still leaves a readable CSV with partial results.
- **UDP scanning:** Many UDP services do not reply to unsolicited probes. A large number of ports may appear `closed` or `filtered` and show timeouts — this is expected.
- **Permissions:** On some systems creating network connections or probing ports may require elevated privileges.
