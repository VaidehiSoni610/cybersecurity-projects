"""
Project 5: Hash Cracker — Dictionary Attack Simulator
Concepts: hashing, dictionary attacks, rainbow tables, salting
"""
import hashlib, time

WORDLIST = ["password","123456","password123","admin","letmein","qwerty","abc123","monkey",
    "dragon","sunshine","iloveyou","welcome","admin123","login","master","hello","shadow",
    "qwerty123","1234567","princess","football","baseball","charlie","michael","jordan",
    "cheese","daniel","computer","jessica","pepper","1234","12345","test","root","secret"]

def hash_password(password, algorithm="sha256", salt=""):
    return hashlib.new(algorithm, (salt + password).encode()).hexdigest()

def dictionary_attack(target_hash, algorithm="sha256", salt=""):
    print(f"\n{'='*55}\n  🔓 Dictionary Attack\n  Hash: {target_hash}\n  Algorithm: {algorithm.upper()}\n{'='*55}\n")
    start = time.time()
    for i, word in enumerate(WORDLIST, 1):
        print(f"  Trying [{i:>2}/{len(WORDLIST)}]: {word:<20}", end="\r")
        if hash_password(word, algorithm, salt) == target_hash:
            elapsed = time.time() - start
            print(f"\n\n  ✅ CRACKED in {elapsed:.4f}s!")
            print(f"  🔑 Password: {word}  ({i} attempts)\n")
            print("  ⚠ Lesson: Weak passwords crack in milliseconds.\n")
            return word
    print(f"\n  ❌ Not found in wordlist. Strong passwords resist dictionary attacks.\n")
    return None

def salting_demo():
    password = input("\nEnter a weak password to demonstrate: ").strip() or "password123"
    plain   = hash_password(password)
    salted1 = hash_password(password, salt="xK9#mQ2z")
    salted2 = hash_password(password, salt="pL5$rN8w")
    print(f"\n  Password     : '{password}'")
    print(f"  No salt      : {plain}")
    print(f"  Salt 'xK9...' : {salted1}")
    print(f"  Salt 'pL5...' : {salted2}")
    print(f"\n  Same password → 3 completely different hashes!")
    print(f"  Salting defeats pre-computed rainbow tables. 🔐\n")

def create_practice_hash():
    demos = ["password","123456","dragon","sunshine","monkey"]
    print("\nWeak passwords to hash:")
    for i, p in enumerate(demos, 1): print(f"  [{i}] {p}")
    choice = input("Choose 1-5: ").strip()
    try:    password = demos[int(choice)-1]
    except: password = "password"
    algo   = input("Algorithm (md5/sha1/sha256): ").strip() or "sha256"
    hashed = hash_password(password, algo)
    print(f"\n  Password : {password}")
    print(f"  {algo.upper()} hash : {hashed}")
    print(f"\n  Now use option [1] to crack it!\n")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   HASH CRACKER                       ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Crack a hash  [2] Create hash   ║")
        print("║  [3] Salting demo  [4] Exit          ║")
        print("╚══════════════════════════════════════╝\n")
        choice = input("Choose: ").strip()
        if choice == '1':
            algo   = input("Algorithm (md5/sha1/sha256): ").strip() or "sha256"
            target = input("Hash to crack: ").strip()
            if target: dictionary_attack(target, algo)
        elif choice == '2': create_practice_hash()
        elif choice == '3': salting_demo()
        elif choice == '4': print("\nGoodbye! Use strong salted passwords. 🔐\n"); break

if __name__ == "__main__":
    main()
