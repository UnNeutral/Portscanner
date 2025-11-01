#!/usr/bin/env python3
from __future__ import annotations
"""
portscanner.py — compact, TCP/UDP port scanner (fixed-save version).

Behaviour changes from previous:
- Opens CSV output immediately and writes header so file always exists.
- Writes rows incrementally as results arrive and flushes to disk.
- Catches KeyboardInterrupt and performs a robust thread cleanup without tracebacks.
- Retains JSON output (written at the end), and raw printing of each result.

Usage examples:
  # TCP scan of localhost ports 1–1024 with CSV output
  python3 portscanner.py 127.0.0.1 1-1024 --threads 40 --yes --output tcp_scan.csv

  # UDP scan of localhost ports 1–1024 with CSV output
  python3 portscanner.py 127.0.0.1 1-1024 --udp --threads 40 --yes --output udp.csv
"""

import argparse
import csv
import json
import logging
import secrets
import socket
import ssl
import sys
import threading
import time
import os
from datetime import datetime
from typing import Dict, List, Optional

# -----------------------
# Configuration
# -----------------------
CSV_FIELDS = [
    "timestamp",
    "port",
    "protocol",
    "status",
    "banner",
    "fingerprint",
    "rtt_ms",
]

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 50

_print_lock = threading.Lock()


# -----------------------
# Helpers
# -----------------------
def setup_logger(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def thread_safe_print(s: str) -> None:
    with _print_lock:
        print(s, flush=True)


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


# -----------------------
# Input parsing helpers
# -----------------------
def parse_port_list(spec: str) -> List[int]:
    """Turn strings like '22,80,8000-8005' into a sorted list."""
    ports: List[int] = []
    if not spec:
        return ports
    for part in spec.split(","):
        piece = part.strip()
        if not piece:
            continue
        if "-" in piece:
            try:
                a_str, b_str = piece.split("-", 1)
                a = int(a_str)
                b = int(b_str)
                if 1 <= a <= b <= 65535:
                    ports.extend(range(a, b + 1))
            except Exception:
                logging.debug("Ignored bad range: %s", piece)
        else:
            try:
                p = int(piece)
                if 1 <= p <= 65535:
                    ports.append(p)
            except Exception:
                logging.debug("Ignored bad port: %s", piece)
    return sorted(set(ports))


def guess_service(banner: Optional[str]) -> Optional[str]:
    """Very small banner fingerprint helper."""
    if not banner:
        return None
    b = banner.lower()
    if b.startswith("ssh-") or "ssh" in b:
        return "ssh"
    if b.startswith("http/") or "get /" in b or "head /" in b or "http" in b:
        return "http"
    if "ftp" in b:
        return "ftp"
    if "smtp" in b or "ehlo" in b:
        return "smtp"
    if "mysql" in b:
        return "mysql"
    if "mongo" in b:
        return "mongodb"
    return "unknown"


def make_empty_result(port: int, proto: str) -> Dict:
    return {
        "timestamp": now_iso(),
        "port": port,
        "protocol": proto,
        "status": "closed",
        "banner": None,
        "fingerprint": None,
        "rtt_ms": None,
    }


# -----------------------
# Probing helpers
# -----------------------
def _http_head(sock: socket.socket, host: str) -> Optional[str]:
    try:
        req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        sock.sendall(req)
        data = sock.recv(2048)
        return data.decode(errors="ignore").strip()
    except Exception:
        return None


def _send_newline(sock: socket.socket) -> Optional[str]:
    try:
        sock.sendall(b"\r\n")
        data = sock.recv(2048)
        return data.decode(errors="ignore").strip()
    except Exception:
        return None


def _recv_once(sock: socket.socket, bufsize: int = 2048) -> Optional[str]:
    try:
        data = sock.recv(bufsize)
        return data.decode(errors="ignore").strip()
    except Exception:
        return None


# -----------------------
# Network operations
# -----------------------
def _create_connection(address: str, port: int, timeout: float) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((address, port), timeout=timeout)
        return s
    except socket.gaierror as e:
        logging.debug("Name error %s:%s -> %s", address, port, e)
    except Exception as e:
        logging.debug("Connect failed %s:%s -> %s", address, port, e)
    return None


def probe_tcp(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    use_tls: bool = False,
    rate_delay: float = 0.0,
) -> Dict:
    """Single TCP port probe. Returns a result dict."""
    res = make_empty_result(port, "TCP")
    start = time.time()

    sock = _create_connection(host, port, timeout)
    if not sock:
        res["rtt_ms"] = round((time.time() - start) * 1000, 2)
        if rate_delay:
            time.sleep(rate_delay)
        return res

    try:
        with sock:
            sock.settimeout(max(0.2, timeout))
            res["status"] = "open"

            if use_tls:
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        cert = ss.getpeercert()
                        subj = None
                        if isinstance(cert, dict):
                            subj = cert.get("subject")
                        res["banner"] = f"tls_cert_subject={subj}"
                except ssl.SSLError as e:
                    logging.debug("TLS handshake failed %s:%s -> %s", host, port, e)
                    res["banner"] = f"tls_error={e}"
                except Exception as e:
                    logging.debug("TLS unexpected error: %s", e)
            else:
                banner = None
                if port in (80, 8080, 8000, 443) or 8000 <= port < 8100:
                    banner = _http_head(sock, host)
                elif port in (21, 25, 465, 587):
                    banner = _send_newline(sock) or _recv_once(sock)
                else:
                    banner = _recv_once(sock)
                    if not banner:
                        try:
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode(errors="ignore").strip()
                        except Exception:
                            banner = None
                res["banner"] = banner

            res["fingerprint"] = guess_service(res["banner"])
    except Exception as e:
        logging.debug("TCP probe exception on %s:%s -> %s", host, port, e)
        if not res.get("banner"):
            res["banner"] = f"error={e}"
    finally:
        res["rtt_ms"] = round((time.time() - start) * 1000, 2)

    if rate_delay:
        time.sleep(rate_delay)
    return res


def _dns_query_payload() -> bytes:
    tid = secrets.randbelow(0x10000)
    header = (
        tid.to_bytes(2, "big")
        + b"\x01\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )
    qname = b"".join(
        len(p).to_bytes(1, "big") + p.encode() for p in "example.com".split(".")
    )
    qname += b"\x00"
    qtype_qclass = b"\x00\x01" + b"\x00\x01"
    return header + qname + qtype_qclass


def probe_udp(
    host: str, port: int, timeout: float = DEFAULT_TIMEOUT, rate_delay: float = 0.0
) -> Dict:
    """Single UDP probe. Best-effort banner retrieval."""
    res = make_empty_result(port, "UDP")
    start = time.time()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            probe = b"\x00"
            if port == 53:
                probe = _dns_query_payload()
            elif port == 123:
                probe = b"\x1b" + 47 * b"\0"
            try:
                s.sendto(probe, (host, port))
                data, _ = s.recvfrom(2048)
                res["status"] = "open"
                res["banner"] = data.decode(errors="ignore").strip()
                res["fingerprint"] = guess_service(res["banner"])
            except socket.timeout:
                pass
            except Exception as e:
                logging.debug("UDP probe error %s:%s -> %s", host, port, e)
    except Exception as e:
        logging.debug("UDP socket setup error: %s", e)
    finally:
        res["rtt_ms"] = round((time.time() - start) * 1000, 2)

    if rate_delay:
        time.sleep(rate_delay)
    return res


# -----------------------
# CLI / Output
# -----------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Simple threaded TCP/UDP port scanner (lab use).")
    p.add_argument("host", help="target host (IP or domain)")
    p.add_argument("ports", help="ports, e.g. 22,80,443 or 1-1024")
    p.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="worker count")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--rate", type=float, default=0.0, help="per-worker delay (s)")
    p.add_argument("--udp", action="store_true", help="scan UDP as well")
    p.add_argument("--tls", action="store_true", help="force TLS probing on TCP")
    p.add_argument("-o", "--output", help=".json or .csv output file")
    p.add_argument("--yes", action="store_true", help="I have permission to scan")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    return p


def save_results(results: List[Dict], path: str) -> None:
    """Fallback: write JSON or CSV at the end (kept for non-csv or final state)."""
    if not results:
        logging.info("No results to save.")
        return
    path = path.strip()
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logging.info("Saved results to %s", path)
        return
    if path.lower().endswith(".csv"):
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_FIELDS)
                for r in results:
                    writer.writerow([
                        r.get("timestamp", ""),
                        r.get("port", ""),
                        r.get("protocol", ""),
                        r.get("status", ""),
                        r.get("banner", "") if r.get("banner") is not None else "",
                        r.get("fingerprint", "") if r.get("fingerprint") is not None else "",
                        r.get("rtt_ms", ""),
                    ])
            logging.info("Saved CSV to %s", path)
        except Exception as e:
            logging.exception("Failed to save CSV: %s", e)
        return
    logging.error("Unsupported output format. Use .json or .csv")


def run_scan() -> int:
    args = build_arg_parser().parse_args()
    setup_logger(args.verbose)

    if not args.yes:
        thread_safe_print("ERROR: must confirm permission to run scans.")
        thread_safe_print("Re-run with --yes after verifying permissions.")
        return 1

    ports = parse_port_list(args.ports)
    if not ports:
        logging.error("No valid ports parsed from '%s'", args.ports)
        return 1

    all_results: List[Dict] = []
    logging.info("Starting scan %s ports=%s", args.host, ports)
    logging.info(
        "Mode: %s | threads=%d | timeout=%.2fs | rate=%.3fs",
        "UDP" if args.udp else "TCP",
        args.threads,
        args.timeout,
        args.rate,
    )

    # Prepare incremental CSV writer if requested
    csv_fh = None
    csv_writer = None
    output_is_csv = False
    out_path = None
    if args.output:
        out_path = args.output.strip()
        if out_path.lower().endswith(".csv"):
            output_is_csv = True
            try:
                csv_fh = open(out_path, "w", newline="", encoding="utf-8")
                csv_writer = csv.writer(csv_fh)
                csv_writer.writerow(CSV_FIELDS)
                csv_fh.flush()
                print(f"[DEBUG] Opened CSV for incremental writing: {out_path}")
            except Exception as e:
                print(f"[!] Failed to open CSV output '{out_path}': {e}")
                csv_fh = None
                csv_writer = None
        else:
            print(f"[DEBUG] Output provided (not .csv): {out_path} — will write at end")

    # thread pool
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = []
        for port in ports:
            if args.udp:
                futures.append(pool.submit(probe_udp, args.host, port, args.timeout, args.rate))
            else:
                use_tls = args.tls or (port in (443, 8443))
                futures.append(pool.submit(probe_tcp, args.host, port, args.timeout, use_tls, args.rate))

        try:
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    logging.debug("Worker exception: %s", e)
                    continue

                # Collect and print
                all_results.append(r)
                thread_safe_print(json.dumps(r))

                # If CSV incremental writer is active, write this row and flush
                if csv_writer:
                    try:
                        csv_writer.writerow([
                            r.get("timestamp", ""),
                            r.get("port", ""),
                            r.get("protocol", ""),
                            r.get("status", ""),
                            r.get("banner", "") if r.get("banner") is not None else "",
                            r.get("fingerprint", "") if r.get("fingerprint") is not None else "",
                            r.get("rtt_ms", ""),
                        ])
                        csv_fh.flush()
                    except Exception as e:
                        print(f"[!] Failed to write row to CSV: {e}")
        except KeyboardInterrupt:
            logging.warning("User cancelled scan.")
            # fall through to graceful cleanup
        finally:
            # close incremental CSV file if open
            if csv_fh:
                try:
                    csv_fh.close()
                    print(f"[DEBUG] Closed incremental CSV file: {out_path}")
                except Exception:
                    pass

    # If user asked for non-csv output (like JSON), write now
    if args.output and not output_is_csv:
        save_results(all_results, out_path)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(run_scan())
    except KeyboardInterrupt:
        # print once for the user's CTRL+C
        print("\n[!] Scan interrupted by user. Shutting down cleanly...")
    except Exception as e:
        print(f"[!] Unexpected error occurred: {e}")
    finally:
        # robust cleanup: give threads a short moment and join politely, ignoring extra interrupts
        import threading as _th
        import time as _time

        _time.sleep(0.3)

        try:
            for t in _th.enumerate():
                if t is _th.main_thread():
                    continue
                try:
                    t.join(timeout=0.1)
                except KeyboardInterrupt:
                    # ignore extra Ctrl+C during cleanup
                    pass
                except Exception:
                    pass
        except Exception:
            pass

        print("[+] Scan finished or stopped safely.")
        # force exit to avoid Python's own thread-shutdown KeyboardInterrupt spam
        os._exit(0)

