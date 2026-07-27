#!/bin/sh

# Copyright (c) 2026, The Tor Project, Inc.
# See LICENSE for licensing information

# Drive fuzz-cell over the length-field boundaries of every cell parser it
# covers. fuzz_static_testcases.sh only runs when TOR_FUZZ_CORPORA points at
# the external corpora repository, so without this the cell parsers get no
# coverage from "make check" at all.
#
# The cases are generated here rather than stored as binaries: they are
# entirely described by a selector, a command and a length, and checking in a
# few hundred opaque blobs to express that would be worse than the loop.

FUZZER="${builddir:-.}/src/test/fuzz/fuzz-cell"

if [ ! -x "$FUZZER" ]; then
    echo "fuzz-cell was not built; skipping."
    exit 77
fi

tmp=$(mktemp -t fuzzcell.XXXXXX) || exit 1
out=$(mktemp -t fuzzcellout.XXXXXX) || exit 1
trap 'rm -f "$tmp" "$out"' 0

# Emit $1 as two big-endian bytes.
be16() {
    printf '%b' "\\0$(printf '%o' $(( ( $1 / 256 ) % 256 )))\\0$(printf '%o' $(( $1 % 256 )))"
}

# Emit $1 zero bytes.
pad() {
    head -c "$1" /dev/zero
}

# Lengths on and around every limit the parsers enforce: the v1 relay header
# offsets (19 and 21 bytes, so 488 and 490), the v0 header (11, so 498), the
# ntor onionskin (84), MAX_CREATE_LEN (505), the cell payload (509), and the
# 16-bit maximum, which no parser may accept.
LENGTHS="0 1 2 84 85 254 255 256 486 488 489 490 491 494 496 498 499 505 506 509 510 65535"

count=0
status=0

for sel in 0 1 2 3 4; do
  for which in 0 1 2 3; do
    for len in $LENGTHS; do
      {
        printf '%b' "\\0$(printf '%o' "$sel")\\0$(printf '%o' "$which")"
        case "$sel" in
          0|1)
            # create/created: handshake type, then handshake length.
            be16 2
            be16 "$len"
            pad 600
            ;;
          4)
            # relay: the v0 length sits at body offset 9, the v1 length at 17,
            # so set both and let the selector decide which format is parsed.
            pad 9
            be16 "$len"
            pad 6
            be16 "$len"
            pad 600
            ;;
          *)
            # extend/extended: the payload starts with the length.
            be16 "$len"
            pad 600
            ;;
        esac
      } > "$tmp"

      if ! "$FUZZER" --err < "$tmp" > "$out" 2>&1; then
          echo "FAIL: fuzz-cell exited non-zero on sel=$sel which=$which len=$len"
          cat "$out"
          status=1
      elif grep -q 'Bug:' "$out"; then
          # A tor_assert_nonfatal() leaves the exit status at zero, so the
          # log is the only signal that the parser tripped over itself.
          echo "FAIL: non-fatal assertion on sel=$sel which=$which len=$len"
          cat "$out"
          status=1
      fi
      count=$(( count + 1 ))
    done
  done
done

if [ "$status" = 0 ]; then
    echo "fuzz-cell: $count boundary cases passed"
fi

exit "$status"
