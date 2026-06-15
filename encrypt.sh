#!/usr/bin/env zsh
# Encrypts all files in input-encrypt/ → output-encrypt/
# Uses Argon2id + AES-256-GCM (post-quantum resistant)

SCRIPT_DIR="${0:A:h}"

mkdir -p "$SCRIPT_DIR/input-encrypt" "$SCRIPT_DIR/output-encrypt" "$SCRIPT_DIR/decrypted"

files=("$SCRIPT_DIR/input-encrypt"/*(N))
if [[ ${#files[@]} -eq 0 ]]; then
  print "No files found in input-encrypt/" >&2
  exit 1
fi

print "Files to encrypt: ${#files[@]}"
for f in "${files[@]}"; do print "  $(basename "$f")"; done
print ""

export ENC_OUTPUT_DIR="$SCRIPT_DIR/output-encrypt"
python3 "$SCRIPT_DIR/_enc_core.py" encrypt "$SCRIPT_DIR/input-encrypt"
