#!/usr/bin/env python3
"""
Post-quantum-resistant file encryption.

Algorithm:
  KDF:    Argon2id  (time=3, memory=64 MiB, parallelism=2, tag=32 bytes)
          - Memory-hard; GPU/ASIC/quantum attacks all bottlenecked by RAM
  Cipher: AES-256-GCM
          - 256-bit key; Grover's algorithm reduces to ~128-bit quantum
            security, still computationally infeasible for any known attacker
  Nonce:  96-bit random per file (safe: one nonce per key, never reused)
  Salt:   256-bit random per file (ensures unique key even for same password)
  AAD:    original filename authenticated alongside ciphertext — swapping
          or renaming .enc files will cause decryption to fail with InvalidTag

File format (.enc):
  [4  bytes] magic  "ENC2"
  [32 bytes] Argon2id salt
  [12 bytes] AES-GCM nonce
  [N  bytes] AES-256-GCM ciphertext + 16-byte auth tag
             (AAD = original source filename, not stored — must match on decrypt)
"""

import sys
import os
import stat
import getpass
from pathlib import Path
from multiprocessing import Pool, cpu_count
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    from argon2.low_level import hash_secret_raw, Type
except ImportError:
    print("Missing dependency. Run: pip3 install argon2-cffi", file=sys.stderr)
    sys.exit(1)

MAGIC      = b"ENC2"
SALT_LEN   = 32
NONCE_LEN  = 12

ARGON2_TIME    = 3       # iterations
ARGON2_MEMORY  = 65_536  # 64 MiB in KiB per worker
ARGON2_THREADS = 2
ARGON2_KEYLEN  = 32      # 256-bit output key

MIN_PASSWORD_LEN = 12


def _worker_count() -> int:
    try:
        import psutil
        free_gib = psutil.virtual_memory().available // (1024 ** 3)
    except ImportError:
        free_gib = 4
    ram_workers = max(1, (free_gib * 1024) // 64)
    cpu_workers = max(1, cpu_count() or 1)
    return min(ram_workers, cpu_workers, 4)


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_THREADS,
        hash_len=ARGON2_KEYLEN,
        type=Type.ID,
    )


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = derive_key(password, salt)
    aad   = src.name.encode("utf-8")  # bind ciphertext to filename
    plaintext  = src.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    dst.write_bytes(MAGIC + salt + nonce + ciphertext)
    dst.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner only


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    data = src.read_bytes()
    if not data.startswith(MAGIC):
        raise ValueError("Not a valid .enc file (bad magic bytes)")
    offset = len(MAGIC)
    salt   = data[offset: offset + SALT_LEN];  offset += SALT_LEN
    nonce  = data[offset: offset + NONCE_LEN]; offset += NONCE_LEN
    ciphertext = data[offset:]
    key   = derive_key(password, salt)
    aad   = src.name.encode("utf-8")  # must match the name used at encrypt time
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    dst.write_bytes(plaintext)
    dst.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner only


# ── worker functions (top-level required for multiprocessing pickling) ─────────
# Workers receive pre-derived (salt, key) bytes — the password never leaves
# the main process and is never pickled or sent over IPC.

def _encrypt_worker(args):
    src_str, dst_str, salt, key = args
    src, dst = Path(src_str), Path(dst_str)
    try:
        nonce = os.urandom(NONCE_LEN)
        aad   = src.name.encode("utf-8")
        plaintext  = src.read_bytes()
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        dst.write_bytes(MAGIC + salt + nonce + ciphertext)
        dst.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return ("ok", src.name, dst.name, None)
    except Exception as e:
        dst.unlink(missing_ok=True)
        return ("fail", src.name, None, str(e))


def _decrypt_worker(args):
    src_str, dst_str, password = args
    src, dst = Path(src_str), Path(dst_str)
    try:
        data = src.read_bytes()
        if not data.startswith(MAGIC):
            raise ValueError("Not a valid .enc file (bad magic bytes)")
        offset = len(MAGIC)
        salt   = data[offset: offset + SALT_LEN];  offset += SALT_LEN
        nonce  = data[offset: offset + NONCE_LEN]; offset += NONCE_LEN
        ciphertext = data[offset:]
        # Salt is per-file so key must be derived per-file in the worker.
        # Password is passed here because each file has a unique salt —
        # there is no way to pre-derive keys in the main process for decrypt.
        key       = derive_key(password, salt)
        aad       = src.name.encode("utf-8")
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        dst.write_bytes(plaintext)
        dst.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return ("ok", src.name, dst.name, None)
    except InvalidTag:
        dst.unlink(missing_ok=True)
        return ("fail", src.name, None, "wrong password or corrupted/renamed file")
    except Exception as e:
        dst.unlink(missing_ok=True)
        return ("fail", src.name, None, str(e))


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} encrypt|decrypt <input_dir>")
        sys.exit(1)

    mode      = sys.argv[1]
    input_dir = Path(sys.argv[2])

    # Read output dir from env (set by shell scripts)
    output_dir = Path(os.environ.get("ENC_OUTPUT_DIR", ""))
    if not output_dir.name:
        print("ENC_OUTPUT_DIR not set", file=sys.stderr)
        sys.exit(1)

    # Password read directly from terminal — never from argv or stdin pipe
    try:
        password = getpass.getpass("Enter password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)

    if len(password) < MIN_PASSWORD_LEN:
        print(f"Password must be at least {MIN_PASSWORD_LEN} characters.", file=sys.stderr)
        sys.exit(1)

    if mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        confirm = ""  # clear immediately

    output_dir.mkdir(parents=True, exist_ok=True)
    # Restrict output directory itself to owner only
    output_dir.chmod(stat.S_IRWXU)

    workers = _worker_count()
    print(f"Parallel workers: {workers}")

    if mode == "encrypt":
        files = sorted(f for f in input_dir.iterdir() if f.is_file())
        # Pre-derive a unique (salt, key) per file in the main process
        # so the plaintext password is never pickled or sent to workers
        tasks = []
        for f in files:
            salt = os.urandom(SALT_LEN)
            key  = derive_key(password, salt)
            tasks.append((str(f), str(output_dir / (f.name + ".enc")), salt, key))
        password = ""  # clear after all keys derived
        worker_fn = _encrypt_worker

    elif mode == "decrypt":
        files = sorted(f for f in input_dir.glob("*.enc") if f.is_file())
        # For decrypt each file has its own salt (read from the file),
        # so we must pass the password to each worker — it stays in local IPC only
        tasks = [(str(f), str(output_dir / f.stem), password) for f in files]
        worker_fn = _decrypt_worker

    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)

    if not tasks:
        print("No files found.")
        return

    success = fail = 0
    with Pool(processes=workers) as pool:
        for status, src_name, dst_name, err in pool.imap_unordered(worker_fn, tasks):
            if status == "ok":
                print(f"✓  {src_name} → {dst_name}")
                success += 1
            else:
                print(f"✗  {src_name} ({err})", file=sys.stderr)
                fail += 1

    print(f"\nDone. {success} {'encrypted' if mode == 'encrypt' else 'decrypted'}, {fail} failed.")
    print(f"Output → {output_dir}")


if __name__ == "__main__":
    main()
