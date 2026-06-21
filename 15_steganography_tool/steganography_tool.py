"""
Project 15: Steganography Tool (Image & Text)
Concepts: steganography, LSB encoding, covert channels, data hiding vs encryption

What you'll learn:
- The difference between steganography and encryption (hiding vs scrambling)
- How Least Significant Bit (LSB) encoding hides data inside image pixels
- How zero-width Unicode characters can hide text inside other text
- Why steganography is used by both privacy advocates and attackers
- How to calculate the maximum hideable data size for a given image

⚠ Built entirely with the Python standard library — includes a from-scratch
  24-bit BMP reader/writer so no image libraries (e.g. Pillow) are required.
"""

import struct
import os

# ── BMP File Handling (built from scratch, no external libraries) ────────────

def create_sample_bmp(filename, width=200, height=200):
    """
    Generate a simple 24-bit uncompressed BMP image — a soft gradient —
    to use as a 'cover image' for hiding secret messages.

    BMP files have a simple structure:
    - 14-byte File Header  (signature, file size, pixel data offset)
    - 40-byte DIB Header   (width, height, bits per pixel, etc.)
    - Pixel data           (BGR bytes, rows padded to multiples of 4, bottom-up)
    """
    row_padding = (4 - (width * 3) % 4) % 4
    pixel_data_size = (width * 3 + row_padding) * height
    file_size = 14 + 40 + pixel_data_size

    # File header (14 bytes)
    file_header = struct.pack(
        '<2sIHHI',
        b'BM',              # signature
        file_size,          # total file size
        0, 0,               # reserved
        14 + 40             # pixel data offset
    )

    # DIB header / BITMAPINFOHEADER (40 bytes)
    dib_header = struct.pack(
        '<IiiHHIIiiII',
        40,                 # header size
        width, height,      # dimensions
        1,                  # color planes
        24,                 # bits per pixel
        0,                  # no compression
        pixel_data_size,    # image data size
        2835, 2835,         # pixels per meter (72 DPI)
        0, 0                # colors used / important
    )

    # Generate a simple diagonal gradient as pixel data (bottom-up, BGR order)
    pixel_rows = bytearray()
    for y in range(height):
        for x in range(width):
            blue  = int(255 * (x / width))
            green = int(255 * (y / height))
            red   = 150
            pixel_rows += bytes([blue, green, red])
        pixel_rows += bytes(row_padding)

    with open(filename, 'wb') as f:
        f.write(file_header)
        f.write(dib_header)
        f.write(pixel_rows)

    print(f"  ✅ Sample cover image created: {filename} ({width}x{height})")

def read_bmp(filename):
    """
    Read a BMP file and return its structure:
    (header_bytes, pixel_data as a mutable bytearray, width, height, pixel_offset)
    """
    with open(filename, 'rb') as f:
        raw = f.read()

    if raw[0:2] != b'BM':
        raise ValueError("Not a valid BMP file")

    pixel_offset = struct.unpack('<I', raw[10:14])[0]
    width        = struct.unpack('<i', raw[18:22])[0]
    height       = struct.unpack('<i', raw[22:26])[0]
    bits_per_px  = struct.unpack('<H', raw[28:30])[0]

    if bits_per_px != 24:
        raise ValueError("Only 24-bit uncompressed BMP files are supported")

    header      = bytearray(raw[:pixel_offset])
    pixel_data  = bytearray(raw[pixel_offset:])

    return header, pixel_data, width, height

def write_bmp(filename, header, pixel_data):
    """Write a BMP file from header + pixel data."""
    with open(filename, 'wb') as f:
        f.write(header)
        f.write(pixel_data)

# ── LSB Steganography Core ─────────────────────────────────────────────────────

def text_to_bits(text):
    """Convert a string to a list of bits (0s and 1s), MSB first per byte."""
    bits = []
    for byte in text.encode('utf-8'):
        bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
    return bits

def bits_to_text(bits):
    """Convert a list of bits back into a string."""
    byte_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]
    byte_values = []
    for chunk in byte_chunks:
        if len(chunk) < 8:
            break
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        byte_values.append(value)
    try:
        return bytes(byte_values).decode('utf-8', errors='ignore')
    except Exception:
        return bytes(byte_values).decode('latin-1', errors='ignore')

def calculate_capacity(pixel_data_length):
    """
    Each pixel byte can hide 1 bit (its LSB).
    32 bits are reserved up front to store the message length.
    """
    usable_bits  = pixel_data_length - 32
    usable_bytes = usable_bits // 8
    return max(0, usable_bytes)

def hide_message_in_bmp(input_bmp, message, output_bmp):
    """
    Hide a text message inside a BMP's pixel data using LSB encoding.
    The first 32 bits store the message length; the rest store the message.
    """
    header, pixel_data, width, height = read_bmp(input_bmp)

    message_bytes = message.encode('utf-8')
    capacity = calculate_capacity(len(pixel_data))

    if len(message_bytes) > capacity:
        print(f"  ❌ Message too large! Max capacity: {capacity} bytes, "
              f"message is {len(message_bytes)} bytes.")
        return False

    # Build the full bitstream: 32-bit length prefix + message bits
    length_bits  = [(len(message_bytes) >> i) & 1 for i in range(31, -1, -1)]
    message_bits = text_to_bits(message)
    all_bits     = length_bits + message_bits

    # Embed each bit into the LSB of successive pixel bytes
    for i, bit in enumerate(all_bits):
        pixel_data[i] = (pixel_data[i] & 0xFE) | bit   # clear LSB, set new bit

    write_bmp(output_bmp, header, pixel_data)

    print(f"  ✅ Message hidden successfully!")
    print(f"  📁 Output       : {output_bmp}")
    print(f"  📏 Message size : {len(message_bytes)} bytes")
    print(f"  📦 Capacity used: {len(message_bytes)}/{capacity} bytes "
          f"({len(message_bytes)/capacity*100:.1f}%)")
    return True

def extract_message_from_bmp(stego_bmp):
    """Extract a hidden message from a BMP's pixel LSBs."""
    _, pixel_data, _, _ = read_bmp(stego_bmp)

    # Read the 32-bit length prefix first
    length_bits = [pixel_data[i] & 1 for i in range(32)]
    message_length = 0
    for bit in length_bits:
        message_length = (message_length << 1) | bit

    if message_length <= 0 or message_length > len(pixel_data):
        print("  ⚠️  No valid hidden message detected in this image.")
        return None

    # Read the message bits that follow
    message_bit_count = message_length * 8
    message_bits = [pixel_data[32 + i] & 1 for i in range(message_bit_count)]

    message = bits_to_text(message_bits)
    return message

# ── Text Steganography (Zero-Width Characters) ────────────────────────────────
# Hides a secret message inside ordinary-looking text using invisible
# Unicode characters. The text LOOKS unchanged but secretly carries data.

ZERO_WIDTH_SPACE     = '\u200b'   # represents bit 0
ZERO_WIDTH_NON_JOINER = '\u200c'  # represents bit 1
ZERO_WIDTH_MARKER    = '\u200d'   # marks end of hidden message

def hide_in_text(cover_text, secret_message):
    """Hide a secret message inside cover text using zero-width characters."""
    bits = text_to_bits(secret_message)
    hidden = ''.join(ZERO_WIDTH_NON_JOINER if b else ZERO_WIDTH_SPACE for b in bits)
    hidden += ZERO_WIDTH_MARKER   # end marker
    # Insert the hidden payload right after the first word
    words = cover_text.split(' ', 1)
    if len(words) == 2:
        return words[0] + hidden + ' ' + words[1]
    return cover_text + hidden

def extract_from_text(stego_text):
    """Extract a hidden message from text containing zero-width characters."""
    bits = []
    for char in stego_text:
        if char == ZERO_WIDTH_SPACE:
            bits.append(0)
        elif char == ZERO_WIDTH_NON_JOINER:
            bits.append(1)
        elif char == ZERO_WIDTH_MARKER:
            break
    if not bits:
        return None
    return bits_to_text(bits)

# ── Educational Explanation ───────────────────────────────────────────────────

def explain_steganography():
    print("""
  📖 STEGANOGRAPHY vs ENCRYPTION — What's the Difference?
  ══════════════════════════════════════════════════════
  ENCRYPTION:       "I see something, but I can't read it."
                     (Obviously scrambled — draws attention)

  STEGANOGRAPHY:     "I don't even know something is there."
                     (Looks completely normal — hides existence itself)

  HOW LSB IMAGE STEGANOGRAPHY WORKS:
  Every pixel has 3 color bytes: Red, Green, Blue (0-255 each).
  Changing the LAST bit of a byte changes the color by AT MOST 1/255.
  That's invisible to the human eye.

    Original pixel byte:  10110110   (value 182)
    Hide bit '1':          10110111   (value 183)  ← imperceptible change!

  By hiding 1 bit per color byte across thousands of pixels, you can
  embed a meaningful amount of text or data with zero visible difference.

  REAL-WORLD USES:
  ✅ Legitimate: watermarking, covert journalism in censored regions,
     proving image ownership, digital forensics watermarks
  ⚠️  Malicious: malware hiding payloads inside seemingly normal images
     (this technique is called "stegware"), exfiltrating stolen data
     past security tools that only scan for known file types

  WHY SECURITY TEAMS CARE:
  Antivirus and DLP (Data Loss Prevention) tools often don't inspect
  image pixel data closely — making steganography a real exfiltration
  risk in corporate environments.
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   STEGANOGRAPHY TOOL                 ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Generate sample cover image     ║")
        print("║  [2] Hide message in image           ║")
        print("║  [3] Extract message from image      ║")
        print("║  [4] Hide message in text            ║")
        print("║  [5] Extract message from text       ║")
        print("║  [6] Calculate image capacity        ║")
        print("║  [7] Steganography explained         ║")
        print("║  [8] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            filename = input("\n  Output filename (default: cover.bmp): ").strip() or "cover.bmp"
            width  = input("  Width (default 200): ").strip()
            height = input("  Height (default 200): ").strip()
            width  = int(width) if width.isdigit() else 200
            height = int(height) if height.isdigit() else 200
            create_sample_bmp(filename, width, height)

        elif choice == "2":
            input_bmp  = input("\n  Cover image filename (default: cover.bmp): ").strip() or "cover.bmp"
            if not os.path.exists(input_bmp):
                print(f"  ❌ '{input_bmp}' not found. Generate one with option [1] first.")
                continue
            message    = input("  Secret message to hide: ").strip()
            output_bmp = input("  Output filename (default: secret.bmp): ").strip() or "secret.bmp"
            print()
            hide_message_in_bmp(input_bmp, message, output_bmp)

        elif choice == "3":
            stego_bmp = input("\n  Stego image filename (default: secret.bmp): ").strip() or "secret.bmp"
            if not os.path.exists(stego_bmp):
                print(f"  ❌ '{stego_bmp}' not found.")
                continue
            message = extract_message_from_bmp(stego_bmp)
            if message:
                print(f"\n  🔓 Hidden message found:")
                print(f"  \"{message}\"\n")

        elif choice == "4":
            cover  = input("\n  Cover text (e.g. a normal sentence): ").strip()
            secret = input("  Secret message to hide: ").strip()
            result = hide_in_text(cover, secret)
            print(f"\n  ✅ Stego text generated (looks identical to the cover text!):")
            print(f"  \"{result}\"")
            print(f"\n  💡 Copy this text anywhere — the hidden message travels with it invisibly.\n")

        elif choice == "5":
            stego_text = input("\n  Paste the stego text: ")
            message = extract_from_text(stego_text)
            if message:
                print(f"\n  🔓 Hidden message found: \"{message}\"\n")
            else:
                print(f"\n  ⚠️  No hidden message detected.\n")

        elif choice == "6":
            filename = input("\n  Image filename (default: cover.bmp): ").strip() or "cover.bmp"
            if not os.path.exists(filename):
                print(f"  ❌ '{filename}' not found.")
                continue
            _, pixel_data, width, height = read_bmp(filename)
            capacity = calculate_capacity(len(pixel_data))
            print(f"\n  📐 Image      : {width}x{height} pixels")
            print(f"  📦 Pixel bytes: {len(pixel_data)}")
            print(f"  💾 Max hideable message: {capacity} bytes (~{capacity} characters)\n")

        elif choice == "7":
            explain_steganography()

        elif choice == "8":
            print("\nGoodbye! Hidden in plain sight. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()
