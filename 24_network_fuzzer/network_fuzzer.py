"""
Project 24: Network Fuzzer
Concepts: fuzzing, buffer overflows, format string vulnerabilities,
          mutation fuzzing, crash detection, vulnerability discovery

What you'll learn:
- What fuzzing is and why it finds bugs that code review misses
- The difference between mutation-based and generation-based fuzzing
- How buffer overflows are discovered by sending oversized input
- What format string, integer boundary, and injection payloads look for
- How real fuzzers like AFL, libFuzzer, Boofuzz, and Peach work
- How to build a safe local test target to fuzz against

Builds on: Project 3 (sockets), Project 17 (HTTP probing),
           Project 18 (packet construction), Project 22 (anomaly detection)

⚠ Only fuzz services you own or have explicit permission to test.
  Fuzzing production systems causes outages and may be illegal.
"""

import socket
import time
import threading
import random
import string
import struct
import json
import os
from datetime import datetime

# ── Payload Library ───────────────────────────────────────────────────────────

def generate_payloads():
    """
    Build a comprehensive set of fuzz payloads targeting different vulnerability classes.
    Each category targets a specific type of bug — understanding WHY each payload works
    is as important as the payload itself.
    """
    payloads = {}

    # ── 1. Buffer Overflow Candidates ─────────────────────────────────────────
    # Send increasingly long strings. When a fixed-size buffer is filled past
    # its end, it overwrites adjacent memory — stack variables, return addresses.
    # The crash site and offset tell you how much to send to control execution.
    payloads['buffer_overflow'] = [
        b'A' * n
        for n in [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536]
    ]

    # Classic Metasploit cyclic patterns — each 4-byte chunk is unique,
    # so if the service crashes and EIP = "Aa0A", you know exactly how
    # many bytes it took to reach the return address.
    payloads['cyclic_pattern'] = [_cyclic_pattern(n) for n in [512, 1024, 2048]]

    # ── 2. Format String Payloads ──────────────────────────────────────────────
    # If user input reaches printf/sprintf directly, %x reads stack memory,
    # %n WRITES to memory. These test whether the service is vulnerable.
    # Real exploits use long chains of %x to leak addresses, then %n to write.
    payloads['format_string'] = [
        b'%x',
        b'%x%x%x%x%x%x%x%x%x%x',
        b'%s%s%s%s%s%s%s%s%s%s',
        b'%n%n%n%n',
        b'%d%d%d%d',
        b'%p%p%p%p%p%p%p%p',
        b'AAAA' + b'%x' * 64,
        b'%08x.' * 20,
    ]

    # ── 3. Integer Boundary Values ────────────────────────────────────────────
    # The "edges" where integers wrap around or overflow.
    # Length fields, array indices, and loop counters all fail here.
    # 0x7FFFFFFF = max signed 32-bit int. Adding 1 makes it negative.
    # 0xFFFFFFFF = max unsigned 32-bit int. Adding 1 wraps to 0.
    payloads['integer_boundaries'] = [
        struct.pack('>I', 0),
        struct.pack('>I', 1),
        struct.pack('>I', 0x7FFFFFFF),   # INT_MAX (signed 32-bit)
        struct.pack('>I', 0x80000000),   # INT_MIN (signed 32-bit, 2's complement)
        struct.pack('>I', 0xFFFFFFFF),   # UINT_MAX (unsigned 32-bit)
        struct.pack('>H', 0xFFFF),       # UINT16_MAX
        struct.pack('>H', 0x0000),       # 0
        struct.pack('>H', 0x8000),       # INT16_MIN
        b'\x00' * 4,
        b'\xff' * 4,
        b'\x7f\xff\xff\xff',
    ]

    # ── 4. Special / Control Characters ──────────────────────────────────────
    # Parsers and protocols fail on unexpected control characters —
    # null bytes truncate C strings, newlines break line-delimited protocols,
    # Unicode characters expose encoding bugs.
    payloads['special_chars'] = [
        b'\x00',                              # null byte
        b'\x00' * 10,
        b'\r\n',                              # CRLF — breaks HTTP/SMTP/FTP parsing
        b'\r\n\r\n',                          # double CRLF — HTTP header terminator
        b'\n' * 100,
        b'\x7f',                              # DEL character
        b'\xff\xfe',                          # UTF-16 BOM
        b'\x1b[A\x1b[B\x1b[C\x1b[D',        # ANSI escape sequences
        b'/../../../etc/passwd',              # directory traversal
        b'\x00' * 100 + b'A' * 100,
        b'A' * 50 + b'\x00' + b'B' * 50,    # null in the middle of data
    ]

    # ── 5. Injection Payloads ─────────────────────────────────────────────────
    # Test whether the service passes input to a shell, SQL engine, or
    # XML parser without sanitisation — same concepts as Project 19 (SQLi)
    # but applied to network protocols rather than web forms.
    payloads['injection'] = [
        b'; ls -la',
        b'| cat /etc/passwd',
        b'`id`',
        b'$(whoami)',
        b"' OR '1'='1'--",
        b'" OR "1"="1"--',
        b'<script>alert(1)</script>',
        b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        b'{{7*7}}',                           # template injection probe
        b'${7*7}',
        b'%{7*7}',
    ]

    # ── 6. Mutation of Valid HTTP Input ───────────────────────────────────────
    # Start from a known-good HTTP request and mutate it systematically.
    # Most real-world bugs are found by mutating valid protocol messages
    # rather than sending completely random bytes.
    base_request = b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    payloads['mutation_http'] = [
        b'GET ' + b'A' * 512 + b' HTTP/1.1\r\nHost: localhost\r\n\r\n',
        b'GET / HTTP/9.9\r\nHost: localhost\r\n\r\n',        # invalid version
        b'GET / HTTP/1.1\r\n' + b'X-Pad: ' + b'A'*8000 + b'\r\n\r\n',
        b'GET / HTTP/1.1\r\nHost: ' + b'A' * 65535 + b'\r\n\r\n',
        b'POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n',   # negative length
        b'POST / HTTP/1.1\r\nContent-Length: 9999999\r\n\r\n',
        b'GET \x00 HTTP/1.1\r\nHost: localhost\r\n\r\n',    # null in URL
        b'\x80' * 4 + b'GET / HTTP/1.1\r\n\r\n',           # high bytes prefix
    ]

    return payloads

def _cyclic_pattern(length):
    """
    Generate a De Bruijn sequence — a cyclic pattern where every
    N-byte subsequence is unique. Used to find exact crash offsets.
    """
    alphabet = string.ascii_lowercase + string.digits
    pattern = bytearray()
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                pattern.extend((a + b + c).encode())
                if len(pattern) >= length:
                    return bytes(pattern[:length])
    return bytes(pattern[:length])

# ── Test Server ───────────────────────────────────────────────────────────────

class VulnerableTestServer:
    """
    A deliberately simple TCP server to fuzz against — runs locally,
    completely safe to crash. Simulates common vulnerable server behaviours:
    - Echoes back what you send
    - Crashes (exits the handler) on payloads containing null bytes or very long input
    - Logs what it receives
    No real vulnerabilities are introduced — this simulates the CONCEPT only.
    """
    def __init__(self, host='127.0.0.1', port=9999):
        self.host     = host
        self.port     = port
        self.running  = False
        self.requests = []

    def handle_client(self, conn, addr):
        """Handle one client connection — log, simulate response, close."""
        try:
            data = conn.recv(4096)
            if not data:
                conn.close()
                return

            self.requests.append({
                'time':    datetime.now().strftime('%H:%M:%S.%f')[:12],
                'from':    addr,
                'size':    len(data),
                'preview': data[:40].hex(),
                'crashed': False,
            })

            # Simulate a crash on very long input (buffer overflow scenario)
            if len(data) > 2048:
                self.requests[-1]['crashed'] = True
                conn.close()
                return

            # Simulate a crash on null byte (C-string truncation vulnerability)
            if b'\x00' in data and len(data) > 10:
                self.requests[-1]['crashed'] = True
                conn.close()
                return

            # Normal: echo response
            response = b'OK: ' + data[:64] + b'\r\n'
            conn.sendall(response)

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self):
        """Start the server in a background thread."""
        self.running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(10)
        self._sock.settimeout(0.5)

        def _serve():
            while self.running:
                try:
                    conn, addr = self._sock.accept()
                    t = threading.Thread(target=self.handle_client, args=(conn, addr))
                    t.daemon = True
                    t.start()
                except socket.timeout:
                    continue
                except Exception:
                    break

        t = threading.Thread(target=_serve)
        t.daemon = True
        t.start()

    def stop(self):
        self.running = False
        try:
            self._sock.close()
        except Exception:
            pass

# ── Fuzzing Engine ────────────────────────────────────────────────────────────

class FuzzResult:
    """Represents the outcome of sending a single fuzz payload."""
    def __init__(self, category, payload, response, response_time, anomaly):
        self.category      = category
        self.payload       = payload
        self.payload_size  = len(payload)
        self.response      = response
        self.response_time = response_time
        self.anomaly       = anomaly    # None or a description of what was unusual

    def is_interesting(self):
        return self.anomaly is not None


def send_payload(host, port, payload, timeout=3.0):
    """
    Send a single fuzz payload to the target and record the result.
    Measures response time (slowness can indicate DoS potential),
    checks for no-response (crash), and captures the response body.
    """
    start = time.time()
    anomaly = None
    response = b''

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)

        try:
            response = sock.recv(4096)
            # Empty response: server closed connection without replying —
            # strong sign the handler crashed or aborted early
            if response == b'' and not anomaly:
                anomaly = "Empty response — server closed without replying (possible crash)"
        except socket.timeout:
            anomaly = "No response received (possible crash / hang)"

        elapsed = time.time() - start

        # Flag unusually slow responses — might indicate DoS vulnerability
        if elapsed > (timeout * 0.8) and not anomaly:
            anomaly = f"Slow response: {elapsed:.2f}s (possible DoS candidate)"

    except ConnectionRefusedError:
        anomaly = "Connection refused (server may have crashed)"
        elapsed = time.time() - start
    except ConnectionResetError:
        anomaly = "Connection reset by server (possible crash)"
        elapsed = time.time() - start
    except socket.timeout:
        anomaly = "Connection timed out (possible hang)"
        elapsed = time.time() - start
    except Exception as e:
        anomaly = f"Unexpected error: {str(e)[:50]}"
        elapsed = time.time() - start
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return FuzzResult(
        category     = '',
        payload      = payload,
        response     = response,
        response_time= elapsed,
        anomaly      = anomaly,
    )


def run_fuzzer(host, port, categories=None, delay=0.05, max_per_category=None):
    """
    Main fuzzing loop — iterates through all payload categories and
    sends each one to the target, logging interesting results.
    """
    all_payloads = generate_payloads()
    if categories:
        all_payloads = {k: v for k, v in all_payloads.items() if k in categories}

    total        = sum(len(v) for v in all_payloads.values())
    sent         = 0
    interesting  = []
    start        = time.time()

    print(f"\n{'='*62}")
    print(f"  🔍 NETWORK FUZZER")
    print(f"{'='*62}")
    print(f"  Target     : {host}:{port}")
    print(f"  Categories : {', '.join(all_payloads.keys())}")
    print(f"  Payloads   : {total} total")
    print(f"  Started    : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*62}\n")
    print(f"  {'#':<6} {'Category':<22} {'Size':>6}  {'Result'}")
    print(f"  {'─'*5} {'─'*21} {'─'*5}  {'─'*35}")

    for category, payloads in all_payloads.items():
        batch = payloads[:max_per_category] if max_per_category else payloads

        for payload in batch:
            sent += 1
            result         = send_payload(host, port, payload)
            result.category = category

            if result.is_interesting():
                icon = '🚨'
                interesting.append(result)
            else:
                icon = '✅'

            preview = payload[:20].hex() if payload else ''
            print(f"  {sent:<6} {category:<22} {len(payload):>6}B  "
                  f"{icon} {result.anomaly or 'Normal response'}")

            time.sleep(delay)

    elapsed = time.time() - start

    print(f"\n{'='*62}")
    print(f"  ✅ Fuzzing complete in {elapsed:.1f}s")
    print(f"  📊 Payloads sent     : {sent}")
    print(f"  🚨 Interesting finds : {len(interesting)}")
    print(f"{'='*62}\n")

    if interesting:
        print(f"  📋 Interesting Results (worth investigating):")
        print(f"  {'─'*55}")
        for r in interesting:
            print(f"\n  🚨 Category : {r.category}")
            print(f"     Size     : {r.payload_size} bytes")
            print(f"     Payload  : {r.payload[:32].hex()}{'...' if len(r.payload)>32 else ''}")
            print(f"     Finding  : {r.anomaly}")

    return interesting


# ── Payload Inspector ─────────────────────────────────────────────────────────

def inspect_payloads():
    """Display all payloads grouped by category with annotations."""
    payloads = generate_payloads()

    descriptions = {
        'buffer_overflow':    'Increasing-length strings to find stack/heap overflows',
        'cyclic_pattern':     'De Bruijn sequence to locate exact crash offset',
        'format_string':      '%x/%n chains to leak/write memory via printf',
        'integer_boundaries': 'Edge values that cause integer overflow/wraparound',
        'special_chars':      'Control chars, null bytes, CRLF injection',
        'injection':          'Shell, SQL, XML, template injection probes',
        'mutation_http':      'Mutated HTTP requests targeting parsing edge cases',
    }

    print(f"\n  📋 Fuzz Payload Library ({sum(len(v) for v in payloads.values())} payloads)\n")

    for category, items in payloads.items():
        desc = descriptions.get(category, '')
        print(f"  ── {category.upper()} ({len(items)} payloads)")
        print(f"     {desc}")
        for i, payload in enumerate(items[:3], 1):
            preview = payload[:32].hex()
            suffix  = '...' if len(payload) > 32 else ''
            print(f"     [{i}] {len(payload):>6}B  {preview}{suffix}")
        if len(items) > 3:
            print(f"     ... and {len(items)-3} more")
        print()

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_fuzzing():
    print("""
  📖 FUZZING — Finding Bugs Machines Find Better Than Humans
  ══════════════════════════════════════════════════════

  WHAT IS FUZZING?
  Fuzzing (fuzz testing) is the practice of sending massive amounts of
  unexpected, malformed, or random input to a program and watching for
  crashes, hangs, or unexpected behaviour. If it crashes → possible vulnerability.

  WHY FUZZING FINDS BUGS CODE REVIEW MISSES:
  Developers test what they expect users to do.
  Fuzzers test what nobody expects — and bugs live at the edge cases.

  A human reviewing code might miss:
    "What happens if someone sends 65,535 bytes to this 256-byte buffer?"
  A fuzzer will find that crash in the first 60 seconds.

  TWO MAIN FUZZING APPROACHES:
  ┌─────────────────────────────────────────────────────┐
  │ MUTATION-BASED (what we mostly do)                  │
  │   Start from a valid input, change bits/bytes       │
  │   Fast to set up, good for known protocols          │
  │   Tools: AFL, libFuzzer, Radamsa                    │
  ├─────────────────────────────────────────────────────┤
  │ GENERATION-BASED (grammar-aware)                    │
  │   Build inputs from scratch using protocol grammar  │
  │   Better protocol coverage, slower to set up        │
  │   Tools: Boofuzz, Peach Fuzzer, Sulley              │
  └─────────────────────────────────────────────────────┘

  WHAT EACH PAYLOAD TYPE TARGETS:

  Buffer Overflow: A fixed-size buffer (char buf[256]) is filled past its
    end, overwriting adjacent memory. Stack smashing can redirect
    execution to attacker-controlled code.
    "Send 256 bytes → crash. Send 512 → return address overwritten."

  Format String: printf(user_input) without %s lets %x read stack memory.
    %n WRITES a value to a memory address. Classic exploitation primitive.

  Integer Boundary: off-by-one at 0x7FFFFFFF→0x80000000 (becomes negative),
    allocation sizes computed from user input become 0 or negative.

  Special Chars: null bytes truncate C strings mid-parse. CRLF splits
    HTTP headers. Unexpected encoding triggers codec errors.

  REAL-WORLD IMPACT OF FUZZING:
  • Google's OSS-Fuzz has found 9,000+ bugs in open-source projects
  • AFL found the famous "ghost" glibc gethostbyname() bug (CVE-2015-0235)
  • Apple, Microsoft, and Google all run continuous fuzzing in CI/CD
  • HeartBleed (OpenSSL 2014) would have been caught by a simple length-field
    fuzz test — the server trusted the client's stated payload length

  HOW WE DETECT A CRASH:
  • Connection refused       → server process died
  • Connection reset         → handler crashed mid-response
  • No response (timeout)    → server hung waiting on something
  • Slow response            → DoS-class bug (CPU/memory exhaustion)

  COVERAGE-GUIDED FUZZING (the real magic):
  Modern fuzzers like AFL instrument the binary to track which code paths
  each input exercises. When a mutation causes a NEW code path to execute,
  it's kept and mutated further. This biases the fuzzer toward unexplored
  corners of the code — much smarter than purely random input.
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    server = None

    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   NETWORK FUZZER                     ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Start local test server         ║")
        print("║  [2] Fuzz the local test server      ║")
        print("║  [3] Fuzz a custom target            ║")
        print("║  [4] Inspect payload library         ║")
        print("║  [5] How fuzzing works (explained)   ║")
        print("║  [6] Stop local test server          ║")
        print("║  [7] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            if server and server.running:
                print("\n  ⚠️  Test server already running on 127.0.0.1:9999\n")
                continue
            server = VulnerableTestServer()
            server.start()
            time.sleep(0.2)
            print("\n  ✅ Test server started on 127.0.0.1:9999")
            print("  Run option [2] to fuzz it.\n")

        elif choice == "2":
            if not server or not server.running:
                print("\n  ❌ Test server not running. Start it with option [1] first.\n")
                continue
            print("\n  ⚠️  Only a few payloads per category for speed.")
            run_fuzzer('127.0.0.1', 9999, max_per_category=3)

            if server.requests:
                crashes = [r for r in server.requests if r['crashed']]
                print(f"\n  Server log: {len(server.requests)} requests received, "
                      f"{len(crashes)} simulated crash(es)\n")

        elif choice == "3":
            print("\n  ⚠️  Only fuzz hosts you own or have written permission to test.\n")
            host = input("  Target host: ").strip()
            if not host:
                continue
            try:
                port = int(input("  Target port: ").strip())
            except ValueError:
                print("  ❌ Invalid port.")
                continue
            cats = input(
                "  Categories (leave blank for all, or: buffer_overflow format_string "
                "special_chars injection): "
            ).strip().split() or None
            run_fuzzer(host, port, categories=cats, max_per_category=5)

        elif choice == "4":
            inspect_payloads()

        elif choice == "5":
            explain_fuzzing()

        elif choice == "6":
            if server and server.running:
                server.stop()
                print("\n  🔴 Test server stopped.\n")
            else:
                print("\n  ⚠️  No server was running.\n")

        elif choice == "7":
            if server and server.running:
                server.stop()
            print("\nGoodbye! Fuzz everything. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()
