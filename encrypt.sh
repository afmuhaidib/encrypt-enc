#!/usr/bin/env zsh

SCRIPT_DIR="${0:A:h}"

files=("$SCRIPT_DIR/files"/*(N))
if [[ ${#files[@]} -eq 0 ]]; then
  print "No files found in $SCRIPT_DIR/files" >&2
  exit 1
fi

print "Files to encrypt: ${#files[@]}"
for f in "${files[@]}"; do print "  $(basename "$f")"; done
print ""

read -rs "PASSWORD?Enter encryption password: "
print ""
read -rs "PASSWORD2?Confirm password: "
print ""

if [[ "$PASSWORD" != "$PASSWORD2" ]]; then
  print "Passwords do not match." >&2
  exit 1
fi

if [[ ${#PASSWORD} -lt 8 ]]; then
  print "Password must be at least 8 characters." >&2
  exit 1
fi

# Pass password via stdin — never via argv (visible in ps aux)
print "$PASSWORD" | python3 "$SCRIPT_DIR/_enc_core.py" encrypt "$SCRIPT_DIR/files" "$SCRIPT_DIR/output"

PASSWORD=""
PASSWORD2=""
