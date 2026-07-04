# 🎯 Project 24 — Network Fuzzer

A structured network fuzzer that generates payloads across seven vulnerability
categories — buffer overflows, format strings, integer boundaries, special
characters, injections, and mutated HTTP — sends them to a target, and flags
crashes, hangs, and unexpected responses.

Includes a built-in safe local test server to fuzz against without needing
any external target.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Fuzzing | Sending unexpected input to find crashes and vulnerabilities |
| Buffer overflow | Oversized input overwrites adjacent memory |
| Format string | `%x`/`%n` in printf reads/writes arbitrary memory |
| Integer boundaries | Edge values (INT_MAX, UINT_MAX) cause wraparound bugs |
| Mutation fuzzing | Starting from valid input and systematically corrupting it |
| Crash detection | Empty response, connection reset, timeout as crash signals |
| Cyclic patterns | De Bruijn sequences to locate exact crash offsets |

## ▶️ How to Run

```bash
python3 network_fuzzer.py
```

Start the local test server first (option 1), then fuzz it (option 2) —
completely safe, self-contained, nothing leaves your machine.

## 🔍 Features

- **62 payloads across 7 categories** — buffer overflow, cyclic pattern,
  format string, integer boundaries, special chars, injection, mutated HTTP
- **Built-in vulnerable test server** — safe local target that simulates crashes
  on oversized and null-byte-containing input
- **Crash detection** — flags empty responses, connection resets, connection
  refused, and slow responses as anomalies worth investigating
- **Interesting result summary** — only reports anomalies, not every clean response
- **Custom target mode** — fuzz any host:port you have permission to test
- Built-in explainer covering mutation vs generation fuzzing, coverage-guided
  fuzzing, and real-world impact (option 5)

## 🧪 Recommended Flow

1. Option 5 — read the fuzzing explainer first
2. Option 4 — inspect the payload library and understand what each category targets
3. Option 1 — start the local test server
4. Option 2 — fuzz it and watch the buffer overflow and null-byte payloads trigger crashes
5. Read the interesting results summary and understand WHY those specific payloads crashed it

## ⚠️ Legal & Ethical Note

Only fuzz services you own or have **explicit written permission** to test.
Fuzzing production systems causes outages, triggers security alerts, and
may violate computer fraud laws. Always use isolated lab environments.

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Application Security — fuzzing, input validation, vulnerability discovery |
| CEH | System Hacking / Web App Hacking — buffer overflows, fuzzing techniques |

## 📖 Key Terms

- **Fuzzing** — sending unexpected input to find crashes and vulnerabilities
- **Buffer overflow** — writing past the end of a fixed-size buffer into adjacent memory
- **Format string vulnerability** — `printf(user_input)` allows `%x`/`%n` to leak or write memory
- **Integer overflow** — arithmetic result exceeds type's max value and wraps around
- **Mutation fuzzing** — starting from valid input and systematically corrupting it
- **Generation fuzzing** — building malformed inputs from a protocol grammar
- **Cyclic / De Bruijn pattern** — sequence where every N-byte chunk is unique, locates crash offset
- **Coverage-guided fuzzing** — fuzzer tracks which code paths each input exercises
- **AFL (American Fuzzy Lop)** — gold standard coverage-guided fuzzer
- **Boofuzz** — Python network protocol fuzzer (successor to Sulley)
