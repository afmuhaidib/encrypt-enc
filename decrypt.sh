#!/usr/bin/env zsh
# Decrypts all .enc files in output-encrypt/ → decrypted/
# Uses Argon2id + AES-256-GCM (post-quantum resistant)

SCRIPT_DIR="${0:A:h}"

mkdir -p "$SCRIPT_DIR/input-encrypt" "$SCRIPT_DIR/output-encrypt" "$SCRIPT_DIR/input-decrypt" "$SCRIPT_DIR/output-decrypt"

files=("$SCRIPT_DIR/input-decrypt"/*.enc(N))
if [[ ${#files[@]} -eq 0 ]]; then
  print "No .enc files found in input-decrypt/" >&2
  exit 1
fi

print "Files to decrypt: ${#files[@]}"
for f in "${files[@]}"; do print "  $(basename "$f")"; done
print ""

export ENC_OUTPUT_DIR="$SCRIPT_DIR/output-decrypt"
python3 "$SCRIPT_DIR/_enc_core.py" decrypt "$SCRIPT_DIR/input-decrypt"
