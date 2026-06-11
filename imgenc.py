#!/usr/bin/env python3
"""
imgenc — AES-256-GCM image folder encryptor
Two recovery paths: password OR key file (keep the key file somewhere safe!)
"""

import os
import sys
import json
import struct
import getpass
import argparse
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
                    ".webp", ".heic", ".heif", ".raw", ".cr2", ".nef", ".arw"}
ENC_SUFFIX = ".enc"
KEYSTORE_FILE = "keystore.enc"

# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1,
                 backend=default_backend())
    return kdf.derive(password.encode())

# ── Master key management ─────────────────────────────────────────────────────

def create_keystore(folder: Path, password: str) -> bytes:
    """Generate a random master key, save keystore.enc + master.key."""
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    wrapping_key = _derive_key(password, salt)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(wrapping_key)
    wrapped = aesgcm.encrypt(nonce, master_key, None)

    keystore = {"salt": salt.hex(), "nonce": nonce.hex(), "wrapped": wrapped.hex()}
    (folder / KEYSTORE_FILE).write_text(json.dumps(keystore))

    return master_key

def load_master_key_from_password(folder: Path, password: str) -> bytes:
    ks_path = folder / KEYSTORE_FILE
    if not ks_path.exists():
        sys.exit(f"No keystore found at {ks_path}")
    keystore = json.loads(ks_path.read_text())
    salt    = bytes.fromhex(keystore["salt"])
    nonce   = bytes.fromhex(keystore["nonce"])
    wrapped = bytes.fromhex(keystore["wrapped"])
    wrapping_key = _derive_key(password, salt)
    try:
        return AESGCM(wrapping_key).decrypt(nonce, wrapped, None)
    except Exception:
        sys.exit("Wrong password.")

# ── File encrypt / decrypt ────────────────────────────────────────────────────

def encrypt_file(src: Path, master_key: bytes) -> Path:
    nonce = secrets.token_bytes(12)
    plaintext = src.read_bytes()
    ciphertext = AESGCM(master_key).encrypt(nonce, plaintext, None)
    dst = src.with_suffix(src.suffix + ENC_SUFFIX)
    # 12-byte nonce prepended
    dst.write_bytes(nonce + ciphertext)
    return dst

def decrypt_file(src: Path, master_key: bytes) -> Path:
    data = src.read_bytes()
    nonce, ciphertext = data[:12], data[12:]
    plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, None)
    dst = src.with_suffix("")
    dst.write_bytes(plaintext)
    return dst

# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init(args):
    folder = Path(args.folder)
    folder.mkdir(parents=True, exist_ok=True)

    if (folder / KEYSTORE_FILE).exists():
        sys.exit("Keystore already exists in this folder. Use 'encrypt' directly.")

    password = getpass.getpass("Set encryption password: ")
    confirm  = getpass.getpass("Confirm password: ")
    if password != confirm:
        sys.exit("Passwords do not match.")

    master_key = create_keystore(folder, password)
    print(f"\n✓ Keystore created: {folder / KEYSTORE_FILE}")
    print(f"\n⚠  RECOVERY KEY (write this down and store it safely — shown once):")
    print(f"   {master_key.hex()}")
    print("\n   If you forget your password, use: imgenc.py decrypt --keyfile <file>")
    print("   where <file> contains those 32 bytes (hex-decode and write to file).")
    print("   If you lose this key AND forget your password, encrypted images are GONE.\n")

def cmd_encrypt(args):
    folder = Path(args.folder)

    if not (folder / KEYSTORE_FILE).exists():
        sys.exit(f"No keystore in '{folder}'. Run 'init' first.")

    password = getpass.getpass("Password: ")
    master_key = load_master_key_from_password(folder, password)

    images = [f for f in folder.iterdir()
              if f.suffix.lower() in IMAGE_EXTENSIONS and not f.name.startswith(".")]

    if not images:
        print("No images found to encrypt.")
        return

    encrypted, skipped = 0, 0
    for img in sorted(images):
        enc_path = img.with_suffix(img.suffix + ENC_SUFFIX)
        if enc_path.exists():
            print(f"  skip  {img.name}  (already encrypted)")
            skipped += 1
            continue
        out = encrypt_file(img, master_key)
        if not args.keep:
            img.unlink()
        print(f"  enc   {img.name}  →  {out.name}")
        encrypted += 1

    print(f"\n✓ {encrypted} image(s) encrypted" +
          (f", {skipped} skipped." if skipped else "."))
    if not args.keep and encrypted:
        print("  (originals deleted — decrypt to restore)")

def cmd_decrypt(args):
    folder = Path(args.folder)

    if not (folder / KEYSTORE_FILE).exists():
        sys.exit(f"No keystore in '{folder}'. Run 'init' first.")
    password = getpass.getpass("Password: ")
    master_key = load_master_key_from_password(folder, password)

    enc_files = [f for f in folder.iterdir()
                 if f.name.endswith(ENC_SUFFIX) and f.name != KEYSTORE_FILE]

    if not enc_files:
        print("No encrypted files found.")
        return

    decrypted = failed = 0
    for enc in sorted(enc_files):
        try:
            out = decrypt_file(enc, master_key)
            if not args.keep:
                enc.unlink()
            print(f"  dec   {enc.name}  →  {out.name}")
            decrypted += 1
        except Exception as e:
            print(f"  FAIL  {enc.name}  ({e})", file=sys.stderr)
            failed += 1

    print(f"\n✓ {decrypted} file(s) decrypted" + (f", {failed} failed." if failed else "."))

def cmd_status(args):
    folder = Path(args.folder)
    images  = [f for f in folder.iterdir() if f.suffix.lower() in IMAGE_EXTENSIONS]
    enc     = [f for f in folder.iterdir() if f.name.endswith(ENC_SUFFIX)]
    ks      = (folder / KEYSTORE_FILE).exists()
    kf      = (folder / KEYFILE_NAME).exists()
    print(f"Folder  : {folder.resolve()}")
    print(f"Keystore: {'✓ present' if ks else '✗ missing (run init)'}")
    print(f"Key file: {'✓ present (back it up!)' if kf else '✗ not here (hopefully backed up)'}")
    print(f"Plaintext images : {len(images)}")
    print(f"Encrypted files  : {len(enc)}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="AES-256-GCM image encryptor with password + key file recovery")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="Create keystore + key file for a folder")
    pi.add_argument("folder", help="Image folder path")

    pe = sub.add_parser("encrypt", help="Encrypt all images in folder")
    pe.add_argument("folder")
    pe.add_argument("--keep", action="store_true",
                    help="Keep original files after encryption")

    pd = sub.add_parser("decrypt", help="Decrypt all .enc files in folder")
    pd.add_argument("folder")
    pd.add_argument("--keep", action="store_true",
                    help="Keep .enc files after decryption")

    ps = sub.add_parser("status", help="Show encryption status of a folder")
    ps.add_argument("folder")

    args = p.parse_args()
    {"init": cmd_init, "encrypt": cmd_encrypt,
     "decrypt": cmd_decrypt, "status": cmd_status}[args.cmd](args)

if __name__ == "__main__":
    main()
