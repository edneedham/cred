#!/bin/sh
set -e

if command -v make >/dev/null 2>&1; then
  make check
else
  echo "make is not installed; run 'cargo fmt --all -- --check' and 'cargo test' manually." >&2
  exit 1
fi