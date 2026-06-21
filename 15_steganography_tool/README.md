# 🖼️ Project 15 — Steganography Tool (Image & Text)

A tool that hides secret messages inside images and plain text using two
different steganography techniques — LSB image encoding and zero-width
Unicode characters. Built entirely from the Python standard library,
including a from-scratch BMP file reader/writer.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Steganography | Hiding the existence of data, not just its content |
| LSB encoding | Hiding bits in the least significant bit of pixel bytes |
| BMP file format | Reading/writing uncompressed images at the byte level |
| Zero-width characters | Hiding text inside other text invisibly |
| Steganography vs encryption | Concealment vs scrambling — different goals |
| Capacity calculation | How much data an image can hide before visible artifacts appear |

## ▶️ How to Run

```bash
python3 steganography_tool.py
```

## 🔍 Features

- **Generate a sample BMP cover image** — no external image needed
- **Hide a message inside an image** using LSB encoding (invisible to the eye)
- **Extract a hidden message** from a stego image
- **Hide a message inside ordinary text** using invisible zero-width characters
- **Extract hidden text** from stego text
- **Capacity calculator** — shows exactly how many bytes an image can hide
- Built-in explanation of how/why steganography is used (option 7)

## 🧪 Recommended Flow

1. Generate a cover image (option 1)
2. Check its capacity (option 6)
3. Hide a secret message in it (option 2)
4. Extract the message back out (option 3) — confirm it matches
5. Try the text version too (options 4 and 5) — paste the output anywhere
   and notice it looks completely unchanged

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Cryptographic Concepts — steganography vs encryption |
| CEH | Cryptography / Covert Channels — data hiding techniques used by attackers |

## 📖 Key Terms

- **Steganography** — hiding the existence of data, not scrambling its content
- **LSB (Least Significant Bit)** — the last bit of a byte; changing it causes minimal visible change
- **Cover image / cover text** — the original file that hides the secret
- **Stego image / stego text** — the file after the secret has been embedded
- **Zero-width characters** — invisible Unicode characters used to hide data in text
- **Stegware** — malware that uses steganography to hide payloads or exfiltrate data
- **Covert channel** — a hidden communication path not intended for that purpose
- **DLP (Data Loss Prevention)** — security tools that try to stop sensitive data leaving a network
