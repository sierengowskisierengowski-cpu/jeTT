#!/usr/bin/env bash
# Deprecated — use: jett  (or ./jett from repo root)
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/jett" "$@"
