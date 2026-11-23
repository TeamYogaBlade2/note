#!/bin/bash
lsmod | awk 'NR>1 {print $1}' | xargs -r modinfo -F filename | sort -u | while read ko; do
  rel=$(echo "$ko" | sed -E 's|.*/kernel/||; s|\.ko(\.zst\|\.xz\|\.gz)?$|.c|')
  if [ -f "$rel" ]; then
    status=$(./scripts/get_maintainer.pl --status --nogit --nogit-fallback -f "$rel" 2>/dev/null | grep -E "Orphan|Obsolete|Odd Fixes")
    if [ -n "$status" ]; then
      echo "[!] $rel -> $status"
    fi
  fi
done
