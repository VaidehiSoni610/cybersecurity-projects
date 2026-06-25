# 📡 Project 18 — Packet Analyzer

Builds and parses raw DNS packets from scratch using only Python's `struct` and
`socket` modules — no external libraries. Shows exactly how data travels across
a network at the binary level, the same way Wireshark does internally.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| DNS packet structure | Building and parsing the 12-byte DNS header + question/answer sections |
| Binary protocols | Using `struct` to pack and unpack raw bytes |
| Pointer compression | How DNS avoids repeating domain names in packets |
| TCP/IP layer model | How Ethernet → IP → TCP/UDP → Application layers stack |
| Hexdump output | Displaying raw bytes the way Wireshark does |
| Record types | A, AAAA, MX, NS, TXT record parsing |

## ▶️ How to Run

```bash
python3 packet_analyzer.py
```

Requires an internet connection for live DNS queries (option 1).
Options 2 and 3 work fully offline.

## 🔍 Features

- **Live DNS analysis** — sends raw DNS queries and parses every byte of the response
- **Multi-record support** — A, AAAA, MX, NS, TXT record parsing
- **Hexdump display** — shows raw packet bytes exactly like Wireshark
- **Byte-by-byte breakdown** — annotates what every byte in a DNS query means
- **TCP/IP layer explainer** — visual walkthrough of the full network stack (option 3)
- **Pointer compression** — handles DNS name compression correctly

## 🧪 Recommended Flow

1. Option 3 — read the layer model explainer first
2. Option 2 — view a DNS query packet's raw bytes and the byte-by-byte annotation
3. Option 1 — query `github.com` for A records and see the real parsed response
4. Option 1 — query `google.com` for MX records and see mail server records
5. Option 1 — try a non-existent domain and observe the NXDOMAIN response code

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Network Security — TCP/IP, DNS, protocol analysis |
| CEH | Sniffing — packet structure, protocol dissection, DNS enumeration |

## 📖 Key Terms

- **Packet** — a unit of data transmitted over a network, containing headers + payload
- **DNS** — Domain Name System — translates domain names to IP addresses
- **struct module** — Python's binary packing/unpacking tool (`>HH` = 2 big-endian shorts)
- **Wire format** — the exact binary representation of data sent over the network
- **Pointer compression** — DNS technique to avoid repeating domain names in packets
- **Hexdump** — display of raw bytes in hex + ASCII, as shown in Wireshark/tcpdump
- **TTL (DNS)** — Time To Live — how many seconds a DNS record can be cached
- **NXDOMAIN** — DNS response code meaning the domain does not exist
- **RCODE** — DNS response code (0=OK, 2=SERVFAIL, 3=NXDOMAIN)
- **Wireshark / tcpdump** — real-world tools that do full packet capture and analysis
