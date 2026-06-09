"""
Project 4: File Integrity Checker
Concepts: hashing (MD5/SHA1/SHA256), tamper detection, digital forensics, baseline snapshots
"""

import hashlib
import os
import json
import time
from datetime import datetime

BASELINE_FILE = "baseline_hashes.json"

# ── Hash Utilities ───────────────────────────────────────────────────────────

def hash_file(filepath, algorithm="sha256"):
    """
    Compute the hash of a file's contents.
    Reads in chunks to handle large files efficiently.
    """
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        return "ERROR:permission_denied"
    except FileNotFoundError:
        return "ERROR:file_not_found"
    except Exception as e:
        return f"ERROR:{str(e)[:30]}"

def hash_string(text, algorithm="sha256"):
    """Hash an arbitrary string."""
    h = hashlib.new(algorithm)
    h.update(text.encode())
    return h.hexdigest()

def compare_hashes(original, current):
    """Constant-time comparison (prevents timing attacks)."""
    return hashlib.compare_digest(original, current)

# ── Baseline Management ──────────────────────────────────────────────────────

def create_baseline(directory, algorithm="sha256"):
    """
    Walk a directory, hash every file, and save results as a baseline.
    This is your 'known-good' snapshot.
    """
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        print(f"\n❌ '{directory}' is not a valid directory.")
        return

    print(f"\n📸 Creating baseline for: {directory}")
    print(f"   Algorithm: {algorithm.upper()}")

    baseline = {
        "metadata": {
            "directory": directory,
            "algorithm": algorithm,
            "created_at": datetime.now().isoformat(),
            "created_ts": time.time(),
        },
        "files": {}
    }

    count = 0
    errors = 0
    for root, dirs, files in os.walk(directory):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for filename in files:
            if filename.startswith('.'):
                continue
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)
            file_hash = hash_file(filepath, algorithm)
            size = os.path.getsize(filepath) if not file_hash.startswith("ERROR") else 0
            baseline["files"][rel_path] = {
                "hash": file_hash,
                "size": size,
                "mtime": os.path.getmtime(filepath) if not file_hash.startswith("ERROR") else 0,
            }
            if file_hash.startswith("ERROR"):
                errors += 1
            else:
                count += 1
            print(f"   ✔ {rel_path}", end="\r")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"\n\n✅ Baseline saved to: {BASELINE_FILE}")
    print(f"   Files hashed : {count}")
    print(f"   Errors       : {errors}")
    print(f"   Timestamp    : {baseline['metadata']['created_at']}\n")

def check_integrity(directory=None):
    """
    Compare current file hashes against the saved baseline.
    Reports: MODIFIED, NEW, and DELETED files.
    """
    if not os.path.exists(BASELINE_FILE):
        print(f"\n❌ No baseline found. Run 'Create Baseline' first.\n")
        return

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    meta = baseline["metadata"]
    check_dir = directory or meta["directory"]
    algorithm = meta["algorithm"]

    print(f"\n🔍 Integrity Check")
    print(f"   Directory : {check_dir}")
    print(f"   Baseline  : {meta['created_at']}")
    print(f"   Algorithm : {algorithm.upper()}")
    print()

    if not os.path.isdir(check_dir):
        print(f"❌ Directory not found: {check_dir}\n")
        return

    baseline_files = baseline["files"]
    current_files  = {}

    for root, dirs, files in os.walk(check_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for filename in files:
            if filename.startswith('.'):
                continue
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, check_dir)
            file_hash = hash_file(filepath, algorithm)
            size = os.path.getsize(filepath) if not file_hash.startswith("ERROR") else 0
            current_files[rel_path] = {"hash": file_hash, "size": size}

    modified = []
    new_files = []
    deleted   = []

    for path, info in current_files.items():
        if path in baseline_files:
            orig_hash = baseline_files[path]["hash"]
            curr_hash = info["hash"]
            if not compare_hashes(orig_hash, curr_hash):
                modified.append((path, orig_hash, curr_hash, info["size"]))
        else:
            new_files.append((path, info["hash"], info["size"]))

    for path in baseline_files:
        if path not in current_files:
            deleted.append(path)

    # Report
    total_issues = len(modified) + len(new_files) + len(deleted)

    if total_issues == 0:
        print("  ✅ All files intact — no changes detected.\n")
        print(f"  Files checked: {len(current_files)}\n")
        return

    print(f"  ⚠  {total_issues} issue(s) detected:\n")

    if modified:
        print(f"  🔴 MODIFIED ({len(modified)}):")
        for path, orig, curr, size in modified:
            print(f"     {path}")
            print(f"       Original : {orig}")
            print(f"       Current  : {curr}")
            print(f"       Size     : {size} bytes")
            print()

    if new_files:
        print(f"  🟡 NEW FILES ({len(new_files)}):")
        for path, h, size in new_files:
            print(f"     {path} ({size} bytes)")
            print(f"       Hash: {h}")
        print()

    if deleted:
        print(f"  🟠 DELETED ({len(deleted)}):")
        for path in deleted:
            print(f"     {path}")
        print()

    print(f"  Files checked: {len(current_files)}")
    print(f"  Baseline had : {len(baseline_files)} files\n")

def hash_demo():
    """Demonstrate hashing concepts interactively."""
    print("\n🧪 Hash Function Demo")
    print("="*55)
    text = input("Enter any text to hash: ")

    print(f"\n  Input: \"{text}\"")
    print(f"\n  {'Algorithm':<12} Hash")
    print(f"  {'-'*11} {'-'*64}")

    for algo in ["md5", "sha1", "sha256", "sha512"]:
        h = hash_string(text, algo)
        print(f"  {algo.upper():<12} {h}")

    print(f"\n🔁 Avalanche Effect — changing one character:")
    if text:
        modified = text[:-1] + chr(ord(text[-1]) + 1) if text else "a"
        h_orig = hash_string(text, "sha256")
        h_mod  = hash_string(modified, "sha256")
        print(f"  Original  : \"{text}\"")
        print(f"  Modified  : \"{modified}\"")
        print(f"\n  SHA-256 original : {h_orig}")
        print(f"  SHA-256 modified : {h_mod}")
        diffs = sum(a != b for a, b in zip(h_orig, h_mod))
        print(f"\n  ⚡ {diffs}/{len(h_orig)} hex chars changed — completely different hash!\n")
        print("  This is the avalanche effect: tiny input change → wildly different hash.\n")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   FILE INTEGRITY CHECKER             ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╚══════════════════════════════════════╝")
        print("\n  [1] Create baseline snapshot")
        print("  [2] Check integrity vs baseline")
        print("  [3] Hash demo (avalanche effect)")
        print("  [4] Exit\n")

        choice = input("Choose an option: ").strip()

        if choice == '1':
            path = input("\nDirectory to snapshot (or '.' for current): ").strip() or "."
            create_baseline(path)

        elif choice == '2':
            check_integrity()

        elif choice == '3':
            hash_demo()

        elif choice == '4':
            print("\nGoodbye! Hashes never lie. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()
