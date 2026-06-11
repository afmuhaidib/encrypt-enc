#!/usr/bin/env python3
"""
AES-256-GCM file encryption with scrypt KDF.

File format (.enc):
  [4 bytes]  magic "ENC1"
  [32 bytes] scrypt salt
  [12 bytes] AES-GCM nonce
  [N bytes]  AES-256-GCM ciphertext+tag (tag is last 16 bytes, appended by AESGCM)
"""

import sys
import os
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"ENC1"
SALT_LEN = 32
NONCE_LEN = 12

# scrypt params: N=2^20 (~1GB RAM, very strong), r=8, p=1
# Use N=2^17 for a balance of speed and security (still strong)
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = src.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    dst.write_bytes(MAGIC + salt + nonce + ciphertext)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    data = src.read_bytes()

    if not data.startswith(MAGIC):
        raise ValueError("Not a valid .enc file (bad magic)")

    offset = len(MAGIC)
    salt = data[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = data[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    dst.write_bytes(plaintext)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} encrypt|decrypt <input_dir> <output_dir>")
        sys.exit(1)

    mode, input_dir, output_dir = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    # Read password from stdin (piped from shell) — never from argv to avoid ps aux leakage
    password = sys.stdin.readline().rstrip("\n")
    output_dir.mkdir(parents=True, exist_ok=True)

    if mode == "encrypt":
        files = [f for f in input_dir.iterdir() if f.is_file()]
        success = fail = 0
        for f in sorted(files):
            out = output_dir / (f.name + ".enc")
            try:
                encrypt_file(f, out, password)
                print(f"✓ Encrypted: {f.name} → {out.name}")
                success += 1
            except Exception as e:
                print(f"✗ Failed:    {f.name} ({e})", file=sys.stderr)
                out.unlink(missing_ok=True)
                fail += 1
        print(f"\nDone. {success} encrypted, {fail} failed.")
        print(f"Output: {output_dir}")

    elif mode == "decrypt":
        files = [f for f in input_dir.glob("*.enc") if f.is_file()]
        success = fail = 0
        for f in sorted(files):
            out = output_dir / f.stem
            try:
                decrypt_file(f, out, password)
                print(f"✓ Decrypted: {f.name} → {out.name}")
                success += 1
            except InvalidTag:
                print(f"✗ Failed:    {f.name} (wrong password or file is corrupt)", file=sys.stderr)
                out.unlink(missing_ok=True)
                fail += 1
            except Exception as e:
                print(f"✗ Failed:    {f.name} ({e})", file=sys.stderr)
                out.unlink(missing_ok=True)
                fail += 1
        print(f"\nDone. {success} decrypted, {fail} failed.")
        print(f"Output: {output_dir}")

    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
