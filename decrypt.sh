#!/usr/bin/env zsh

SCRIPT_DIR="${0:A:h}"

files=("$SCRIPT_DIR/output"/*.enc(N))
if [[ ${#files[@]} -eq 0 ]]; then
  print "No .enc files found in $SCRIPT_DIR/output" >&2
  exit 1
fi

print "Files to decrypt: ${#files[@]}"
for f in "${files[@]}"; do print "  $(basename "$f")"; done
print ""

read -rs "PASSWORD?Enter decryption password: "
print ""

python3 "$SCRIPT_DIR/_enc_core.py" decrypt "$SCRIPT_DIR/output" "$SCRIPT_DIR/decrypted" "$PASSWORD"

PASSWORD=""
