#!/bin/sh
# Wall-clock guard, baked into the image so no security-relevant flag ever has to
# travel through a caller's argv (and so a repo cannot ignore the first signal).
#
# usage: guard.sh <seconds> <absolute-script-path>

set -eu

SECS="${1:-}"
SCRIPT="${2:-}"

case "${SECS}" in
  ''|*[!0-9]*) echo "guard: seconds must be a positive integer" >&2; exit 2 ;;
esac

case "${SCRIPT}" in
  /job/*|/probe/*) ;;
  *) echo "guard: refusing script outside /job and /probe" >&2; exit 2 ;;
esac

exec timeout --signal=TERM --kill-after=5s "${SECS}" /usr/bin/python3 "${SCRIPT}"
