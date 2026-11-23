#!/bin/bash
lsmod | awk 'NR>1 {print $1}' | xargs -r modinfo -F filename | sort -u | while read ko; do
  rel=$(echo "$ko" | sed -E 's|.*/kernel/||; s|\.ko(\.zst\|\.xz\|\.gz)?$||')
  status=$(./scripts/get_maintainer.pl --status --nogit --nogit-fallback -f "${rel}.c" 2>/dev/null)
  [ -z "$status" ] && status=$(./scripts/get_maintainer.pl --status --nogit --nogit-fallback -f "$(dirname "$rel")/" 2>/dev/null)
  echo "$status" | grep -qE "Orphan|Obsolete|Odd Fixes" && echo "[!] $rel -> $(echo "$status" | tr '\n' ' ')"
done
