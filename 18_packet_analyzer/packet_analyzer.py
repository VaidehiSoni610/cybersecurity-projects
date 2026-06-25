"""
Project 18: Packet Analyzer
Concepts: DNS packet structure, binary protocols, struct parsing,
          TCP/IP layers, network forensics, protocol analysis

What you'll learn:
- How data is broken into packets and what each packet contains
- How to read and write raw binary protocols using struct
- How DNS queries and responses work at the byte level
- What the TCP/IP layer model means in practice
- How Wireshark and tcpdump parse the same data we parse here

Note: This project uses UDP sockets for DNS (no root required on Mac).
      Real full packet capture (like Wireshark) needs root + pcap library.
      This is the closest you can get with the standard library alone.
"""

import socket
import struct
import random
import time
from datetime import datetime

# ── DNS Packet Builder ────────────────────────────────────────────────────────

def build_dns_query(domain, query_type=1):
    """
    Build a raw DNS query packet from scratch.
    DNS uses a specific binary format — we build every byte manually.

    DNS packet structure:
    ┌─────────────────────────────────┐
    │  Header (12 bytes)              │
    │  Question section               │
    └─────────────────────────────────┘

    Header fields (2 bytes each):
    - Transaction ID  : random number to match queries to responses
    - Flags           : QR=0 (query), Opcode=0 (standard), RD=1 (recursion desired)
    - Question count  : 1
    - Answer count    : 0 (we're asking, not answering)
    - Authority count : 0
    - Additional count: 0
    """
    transaction_id = random.randint(0, 65535)

    # Flags: 0x0100 = standard query with recursion desired
    flags          = 0x0100
    qdcount        = 1       # one question
    ancount        = 0
    nscount        = 0
    arcount        = 0

    # Pack header as 6 × 16-bit big-endian unsigned integers
    header = struct.pack('>HHHHHH',
        transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Encode the domain name into DNS wire format:
    # "github.com" → \x06github\x03com\x00
    # Each label is prefixed by its length byte, terminated by \x00
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += b'\x00'

    # Append QTYPE (1=A, 28=AAAA, 15=MX, 2=NS, 16=TXT) and QCLASS (1=IN)
    question += struct.pack('>HH', query_type, 1)

    return header + question, transaction_id

# ── DNS Packet Parser ─────────────────────────────────────────────────────────

QUERY_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT',
               28: 'AAAA', 33: 'SRV', 255: 'ANY'}

RESPONSE_CODES = {
    0: '✅ NOERROR   — Success',
    1: '❌ FORMERR   — Format error in query',
    2: '❌ SERVFAIL  — Server failed',
    3: '❌ NXDOMAIN  — Domain does not exist',
    4: '❌ NOTIMP    — Not implemented',
    5: '❌ REFUSED   — Query refused',
}

def parse_dns_name(data, offset):
    """
    Parse a DNS domain name from a packet, handling pointer compression.
    DNS uses a clever compression scheme: if two bytes have 0xC0 in the top bits,
    it's a pointer to another location in the packet (avoids repeating names).

    IMPORTANT: when a pointer is followed, we must return the offset AFTER the
    2-byte pointer (not wherever the pointer leads), so the caller continues
    reading the rest of the record correctly.
    """
    labels      = []
    return_offset = -1   # offset to return to caller (set on first pointer or end of name)

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        # Pointer compression: top 2 bits are 1 (0xC0 = 11000000)
        if length & 0xC0 == 0xC0:
            if return_offset == -1:
                return_offset = offset + 2   # caller resumes AFTER the 2 pointer bytes
            pointer = struct.unpack('>H', data[offset:offset+2])[0] & 0x3FFF
            offset  = pointer
            continue

        # End of name
        if length == 0:
            if return_offset == -1:
                return_offset = offset + 1   # caller resumes after the \x00 terminator
            break

        offset += 1
        labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
        offset += length

    return '.'.join(labels), return_offset if return_offset != -1 else offset

def parse_dns_response(data, expected_id):
    """
    Parse a raw DNS response packet and extract all records.
    Returns a dict with header info and answer/authority/additional records.
    """
    if len(data) < 12:
        return None

    # Unpack the 12-byte header
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])

    if txid != expected_id:
        return None   # Response doesn't match our query

    # Parse flags bitfield
    qr      = (flags >> 15) & 1   # 0=query, 1=response
    opcode  = (flags >> 11) & 0xF
    aa      = (flags >> 10) & 1   # authoritative answer
    tc      = (flags >> 9)  & 1   # truncated
    rd      = (flags >> 8)  & 1   # recursion desired
    ra      = (flags >> 7)  & 1   # recursion available
    rcode   = flags & 0xF          # response code

    result = {
        'transaction_id': txid,
        'is_response':    bool(qr),
        'authoritative':  bool(aa),
        'truncated':      bool(tc),
        'recursion':      bool(ra),
        'rcode':          rcode,
        'rcode_text':     RESPONSE_CODES.get(rcode, f'Unknown ({rcode})'),
        'answers':        [],
        'authority':      [],
        'additional':     [],
    }

    # Skip past the question section
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4   # skip QTYPE + QCLASS

    # Parse answer records
    def parse_records(count):
        records = []
        nonlocal offset
        for _ in range(count):
            if offset + 10 > len(data):
                break
            name, offset  = parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset+10])
            offset += 10
            rdata_raw = data[offset:offset+rdlength]
            offset += rdlength

            rdata_str = parse_rdata(rtype, rdata_raw, data)
            records.append({
                'name':   name,
                'type':   QUERY_TYPES.get(rtype, str(rtype)),
                'class':  rclass,
                'ttl':    ttl,
                'rdata':  rdata_str,
            })
        return records

    result['answers']    = parse_records(ancount)
    result['authority']  = parse_records(nscount)
    result['additional'] = parse_records(arcount)

    return result

def parse_rdata(rtype, rdata, full_packet):
    """Parse the record data based on record type."""
    try:
        if rtype == 1 and len(rdata) == 4:
            # A record — IPv4 address (4 bytes)
            return socket.inet_ntoa(rdata)

        elif rtype == 28 and len(rdata) == 16:
            # AAAA record — IPv6 address (16 bytes)
            return socket.inet_ntop(socket.AF_INET6, rdata)

        elif rtype in (2, 5, 12):
            # NS, CNAME, PTR — domain name in wire format
            name, _ = parse_dns_name(rdata, 0)
            return name

        elif rtype == 15:
            # MX record — 2-byte preference + domain name
            pref = struct.unpack('>H', rdata[:2])[0]
            name, _ = parse_dns_name(rdata, 2)
            return f"priority={pref} {name}"

        elif rtype == 16:
            # TXT record — length-prefixed strings
            parts = []
            i = 0
            while i < len(rdata):
                length = rdata[i]
                i += 1
                parts.append(rdata[i:i+length].decode('utf-8', errors='replace'))
                i += length
            return ' '.join(parts)

        else:
            return rdata.hex()

    except Exception:
        return rdata.hex()

# ── DNS Query Engine ──────────────────────────────────────────────────────────

def send_dns_query(domain, query_type=1, nameserver='8.8.8.8', port=53, timeout=3):
    """
    Send a raw DNS query to a nameserver and return the parsed response.
    Uses UDP socket (DNS default) — no root required on Mac.
    """
    packet, txid = build_dns_query(domain, query_type)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (nameserver, port))
        response_data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_response(response_data, txid), packet, response_data
    except socket.timeout:
        return None, packet, None
    except Exception as e:
        return None, packet, None

# ── Packet Display ────────────────────────────────────────────────────────────

def hexdump(data, bytes_per_row=16):
    """
    Display raw bytes in classic hexdump format — just like Wireshark.
    Shows: offset | hex values | ASCII printable characters
    """
    print(f"\n  📦 Raw bytes ({len(data)} total):")
    print(f"  {'─'*60}")
    for i in range(0, len(data), bytes_per_row):
        chunk  = data[i:i+bytes_per_row]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04X}  {hex_part:<{bytes_per_row*3}}  {ascii_part}")
    print()

def display_dns_result(domain, qtype_name, result, query_packet, response_packet):
    """Print a formatted DNS analysis report."""
    print(f"\n{'='*60}")
    print(f"  📡 DNS PACKET ANALYSIS")
    print(f"{'='*60}")
    print(f"  Domain  : {domain}")
    print(f"  Type    : {qtype_name}")
    print(f"  Server  : 8.8.8.8 (Google Public DNS)")
    print(f"  Time    : {datetime.now().strftime('%H:%M:%S')}")

    if result is None:
        print(f"\n  ❌ No response received (timeout or error)\n")
        return

    print(f"\n  📋 Response Header")
    print(f"  {'─'*50}")
    print(f"  Transaction ID : 0x{result['transaction_id']:04X}")
    print(f"  Response code  : {result['rcode_text']}")
    print(f"  Authoritative  : {'Yes' if result['authoritative'] else 'No'}")
    print(f"  Recursion      : {'Available' if result['recursion'] else 'Not available'}")
    print(f"  Answers        : {len(result['answers'])}")

    if result['answers']:
        print(f"\n  📬 Answer Records")
        print(f"  {'─'*50}")
        print(f"  {'Name':<30} {'Type':<8} {'TTL':<8} Value")
        print(f"  {'─'*28} {'─'*6} {'─'*6} {'─'*20}")
        for rec in result['answers']:
            print(f"  {rec['name']:<30} {rec['type']:<8} {rec['ttl']:<8} {rec['rdata']}")

    if result['authority']:
        print(f"\n  🏛  Authority Records")
        print(f"  {'─'*50}")
        for rec in result['authority']:
            print(f"  {rec['type']:<8} {rec['name']:<25} → {rec['rdata']}")

    # Show query packet hexdump
    print(f"\n  🔵 Query packet  ({len(query_packet)} bytes):")
    hexdump(query_packet)

    if response_packet:
        print(f"  🟢 Response packet  ({len(response_packet)} bytes):")
        hexdump(response_packet[:64])   # first 64 bytes for readability
        if len(response_packet) > 64:
            print(f"  ... ({len(response_packet) - 64} more bytes)\n")

# ── TCP/IP Layer Explainer ────────────────────────────────────────────────────

def explain_packet_structure():
    print("""
  📖 HOW PACKETS ARE STRUCTURED — The TCP/IP Layer Model
  ══════════════════════════════════════════════════════

  Data travelling across the internet is wrapped in multiple layers
  of headers — like envelopes inside envelopes. Each layer adds
  information needed for that layer's job.

  WHEN YOU VISIT https://github.com:

  Layer 4 — APPLICATION (HTTP/DNS/TLS)
  ┌─────────────────────────────────────────────────────┐
  │  GET /index.html HTTP/1.1                           │
  │  Host: github.com                                   │
  └─────────────────────────────────────────────────────┘

  Layer 3 — TRANSPORT (TCP/UDP)
  ┌─────────────────────────────────────────────────────┐
  │  Src port: 54321  │  Dst port: 443  │  Seq: 1000   │
  │  Flags: SYN       │  Window: 65535  │  Checksum    │
  └─────────────────────────────────────────────────────┘

  Layer 2 — INTERNET (IP)
  ┌─────────────────────────────────────────────────────┐
  │  Src IP: 192.168.1.5  │  Dst IP: 140.82.121.3      │
  │  TTL: 64              │  Protocol: TCP (6)          │
  └─────────────────────────────────────────────────────┘

  Layer 1 — NETWORK ACCESS (Ethernet)
  ┌─────────────────────────────────────────────────────┐
  │  Src MAC: AA:BB:CC:DD:EE:FF  │  Dst MAC: 11:22:... │
  │  EtherType: 0x0800 (IPv4)                           │
  └─────────────────────────────────────────────────────┘

  DNS PACKET HEADER (12 bytes — what we built from scratch):
  ┌──────────┬──────────┬──────────┬──────────┐
  │  TxID    │  Flags   │ QDCount  │ ANCount  │  (2 bytes each)
  │ 0x1A2B   │ 0x0100   │  0x0001  │  0x0000  │
  └──────────┴──────────┴──────────┴──────────┘

  FLAGS breakdown (16 bits):
  Bit 15: QR   (0=query, 1=response)
  Bits 11-14: Opcode (0=standard query)
  Bit 10: AA  (authoritative answer)
  Bit 9:  TC  (truncated)
  Bit 8:  RD  (recursion desired) ← we set this to 1
  Bit 7:  RA  (recursion available)
  Bits 0-3: RCODE (0=ok, 3=NXDOMAIN, 2=SERVFAIL)

  WHY THIS MATTERS FOR SECURITY:
  Packet analysis is how defenders detect:
  • DNS exfiltration — data smuggled inside DNS queries
  • Malware C2 traffic — suspicious packet patterns
  • Port scanning — flood of SYN packets with no ACK
  • DDoS — abnormally high traffic from many sources
  Tools like Wireshark, tcpdump, and Zeek do exactly this.
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

QUERY_TYPE_MAP = {'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2, 'TXT': 16}

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   PACKET ANALYZER                    ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Analyze a DNS query (live)      ║")
        print("║  [2] Inspect raw packet bytes        ║")
        print("║  [3] How packets are structured      ║")
        print("║  [4] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            domain = input(
                "\n  Domain to query (e.g. github.com): "
            ).strip().lower()
            if not domain:
                print("  ❌ No domain entered.")
                continue

            print("  Record types: A  AAAA  MX  NS  TXT")
            qtype_input = input("  Record type (default A): ").strip().upper() or 'A'
            qtype_num   = QUERY_TYPE_MAP.get(qtype_input, 1)

            print(f"\n  Sending DNS query for {domain} ({qtype_input})...")
            result, query_pkt, response_pkt = send_dns_query(
                domain, query_type=qtype_num
            )
            display_dns_result(domain, qtype_input, result, query_pkt, response_pkt)

        elif choice == "2":
            print("\n  Build a sample DNS query and view its raw bytes:\n")
            domain = input("  Domain (default: example.com): ").strip() or "example.com"
            packet, txid = build_dns_query(domain)
            print(f"\n  DNS query for '{domain}' ({len(packet)} bytes):")
            hexdump(packet)

            # Walk through the bytes with annotations
            print(f"  📝 Byte-by-byte breakdown:")
            print(f"  {'─'*50}")
            print(f"  Bytes  0- 1 : Transaction ID   = 0x{txid:04X}")
            print(f"  Bytes  2- 3 : Flags            = 0x0100 (standard query, recursion desired)")
            print(f"  Bytes  4- 5 : Question count   = 1")
            print(f"  Bytes  6- 7 : Answer count     = 0 (we're asking)")
            print(f"  Bytes  8- 9 : Authority count  = 0")
            print(f"  Bytes 10-11 : Additional count = 0")
            print(f"  Bytes 12+   : Question section (domain name in wire format)")

            labels = domain.split('.')
            offset = 12
            for label in labels:
                print(f"  Byte  {offset:>4}  : Length prefix = {len(label)} ('{label}')")
                offset += 1 + len(label)
            print(f"  Byte  {offset:>4}  : \\x00 (end of name)")
            print(f"  Bytes {offset+1:>2}-{offset+2:>2} : QTYPE = 0x0001 (A record)")
            print(f"  Bytes {offset+3:>2}-{offset+4:>2} : QCLASS = 0x0001 (Internet)\n")

        elif choice == "3":
            explain_packet_structure()

        elif choice == "4":
            print("\nGoodbye! Every byte tells a story. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()
