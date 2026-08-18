#!/usr/bin/env bash
# archive-graph.sh — losslessly compress PageGraph .graphml files for archival.
#
#   analysis/archive-graph.sh <graphml-or-dir> [more ...]
#   analysis/archive-graph.sh --reclaim <graphml-or-dir> [more ...]
#
# WHY NOT PRUNE FIRST: measured on walmart (1,143,132,196 B), the edge `stack trace` attribute is
# 91.4% of the file (99.2% on delta) — 110,905 stacks that are only 14,013 distinct values, because
# the engine stores each edge's stack as its own std::string with no interning. That redundancy is
# exactly what a compressor is for. Running prune-graph.py --max-frames 25 first destroys 646 MB
# and 45% of every call frame, permanently, and buys 208,670 bytes once compressed — a 3.4%
# improvement. So archiving here is lossless and prune-graph.py keeps its real job, which is making
# a graph tractable to ANALYSE, not to store.
#
# WHY --long=31: stack values average 9,423 B and repeat at a median distance of 12,331 B, so
# gzip's 32 KB window holds about three of them and 36.2% of all repeats are further apart than the
# window can reach. Widening the window is the entire difference between gzip -9 at 42.97x and
# zstd -19 --long=31 at 184.2x, for the same ~9 s/GB:
#
#     gzip -9              26,602,721 B    42.97x
#     zstd -19             7,292,402 B    156.8x
#     zstd -19 --long=31   6,206,822 B    184.2x   <- chosen
#     xz -9                6,681,752 B    171.1x
#
# THE DECOMPRESSION TRAP, verified not assumed: a large window is recorded in the frame header and
# exceeds zstd's default 128 MiB decode budget, so a plain `zstd -d` REFUSES the file:
#
#     bf.zst : Decoding error (36) : Frame requires too much memory for decoding
#     bf.zst : Window size larger than maximum : 141104116 > 134217728
#     bf.zst : Use --long=28 or --memory=135MB
#
# zstd names the exact flag needed, but the number differs per file (it shrinks the window to the
# input size). --long=31 is the upper bound and always works, so that is what every manifest and
# every doc here prints. An archive nobody can open is worse than no archive.
#
# Originals are NEVER deleted by a normal run — the archive is written alongside. Disk therefore
# goes UP until you come back with --reclaim, which is the flag that actually banks the saving and
# which refuses to delete anything it has not just re-verified byte-for-byte.

set -uo pipefail

ZSTD_FLAGS="-19 --long=31 -T0"
RESTORE_CMD_TMPL="zstd -d --long=31 %s"
SELF="$(basename "${BASH_SOURCE[0]}")"

RECLAIM=0
PATHS=""
FAILURES=0
N_OK=0
TOTAL_IN=0
TOTAL_OUT=0

usage() {
  cat <<EOF
$SELF — losslessly archive PageGraph .graphml with zstd -19 --long=31

  analysis/$SELF <graphml-or-dir> [more ...]      compress; keep the original
  analysis/$SELF --reclaim <graphml-or-dir> ...   delete originals that verify

Writes <graph>.graphml.zst plus a <graph>.graphml.archive.json manifest.
Typically ~180x. Nothing is discarded: the graph round-trips byte-for-byte.

TO RESTORE — the plain command does not work, this one does:

  zstd -d --long=31 page_graph_....graphml.zst

A plain 'zstd -d' fails with "Frame requires too much memory for decoding".
The analysis scripts cannot read .zst; decompress before running them.

--reclaim removes an original only when its .zst re-verifies against the
SHA-256 in the manifest. Never deletes on a missing or mismatched check.
EOF
}

log() { printf '%s\n' "$*" >&2; }

# Bytes -> human, for the progress lines only. Manifests always carry exact byte counts.
human() {
  awk -v b="$1" 'BEGIN{
    split("B KB MB GB TB", u, " "); i=1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    printf (i==1 ? "%d %s" : "%.1f %s"), b, u[i]
  }'
}

archive_one() {
  graph="$1"
  zst="$graph.zst"
  manifest="$graph.archive.json"

  case "$graph" in
    *.zst) log "  skip (already compressed): $graph"; return 0 ;;
    *.tmp) log "  skip (crawl temp file):    $graph"; return 0 ;;
  esac

  if [ ! -f "$graph" ]; then
    log "  MISSING: $graph"; return 1
  fi

  in_size=$(wc -c < "$graph" | tr -d ' ')

  if [ "$RECLAIM" -eq 1 ]; then
    reclaim_one "$graph" "$zst" "$manifest"
    return $?
  fi

  if [ -f "$zst" ] && [ -f "$manifest" ]; then
    log "  skip (already archived):   $graph"
    return 0
  fi

  log "  $graph"
  log "    size $(human "$in_size")  hashing..."
  in_sha=$(shasum -a 256 "$graph" | awk '{print $1}')
  [ -n "$in_sha" ] || { log "    FAILED: could not hash source"; return 1; }

  log "    compressing (zstd $ZSTD_FLAGS)..."
  # shellcheck disable=SC2086
  if ! zstd $ZSTD_FLAGS -q -f -o "$zst" "$graph"; then
    log "    FAILED: zstd returned non-zero"
    rm -f "$zst"
    return 1
  fi

  out_size=$(wc -c < "$zst" | tr -d ' ')

  # Verify through a pipe rather than decompressing to disk. On a 7 GB graph a temp file would
  # need 7 GB of free space to prove something a stream proves for nothing.
  log "    verifying round-trip..."
  rt_sha=$(zstd -dc --long=31 "$zst" | shasum -a 256 | awk '{print $1}')

  if [ "$rt_sha" != "$in_sha" ]; then
    log "    FAILED: round-trip mismatch — archive discarded"
    log "      source:     $in_sha"
    log "      round-trip: ${rt_sha:-<none>}"
    rm -f "$zst"
    return 1
  fi

  ratio=$(awk -v a="$in_size" -v b="$out_size" 'BEGIN{ printf "%.1f", (b>0 ? a/b : 0) }')
  restore=$(printf "$RESTORE_CMD_TMPL" "$(basename "$zst")")

  cat > "$manifest" <<EOF
{
  "tool": "$SELF",
  "archivedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "original": "$(basename "$graph")",
  "originalBytes": $in_size,
  "originalSha256": "$in_sha",
  "archive": "$(basename "$zst")",
  "archiveBytes": $out_size,
  "ratio": $ratio,
  "codec": "zstd",
  "codecFlags": "$ZSTD_FLAGS",
  "verified": "sha256 round-trip matched at archive time",
  "restoreCommand": "$restore",
  "restoreNote": "A plain 'zstd -d' fails: the frame window exceeds zstd's default 128 MiB decode budget. --long=31 is required. The analysis scripts cannot read .zst directly.",
  "originalRetained": true
}
EOF

  log "    ok  $(human "$in_size") -> $(human "$out_size")  (${ratio}x)"
  N_OK=$((N_OK + 1))
  TOTAL_IN=$((TOTAL_IN + in_size))
  TOTAL_OUT=$((TOTAL_OUT + out_size))
  return 0
}

# Delete an original only after re-proving the archive reproduces it exactly. The manifest's
# recorded hash is not trusted on its own — it is compared against a hash taken right now, so a
# corrupted or truncated .zst can never authorise a delete.
reclaim_one() {
  graph="$1"; zst="$2"; manifest="$3"

  if [ ! -f "$zst" ]; then
    log "  refuse (no archive):   $graph"; return 1
  fi
  if [ ! -f "$manifest" ]; then
    log "  refuse (no manifest):  $graph"; return 1
  fi

  want=$(sed -n 's/.*"originalSha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$manifest" | head -1)
  if [ -z "$want" ]; then
    log "  refuse (manifest has no originalSha256): $graph"; return 1
  fi

  log "  verifying $zst ..."
  got=$(zstd -dc --long=31 "$zst" | shasum -a 256 | awk '{print $1}')

  if [ "$got" != "$want" ]; then
    log "  REFUSE (hash mismatch — archive is NOT a faithful copy): $graph"
    log "    manifest:   $want"
    log "    round-trip: ${got:-<none>}"
    return 1
  fi

  freed=$(wc -c < "$graph" | tr -d ' ')
  rm -f "$graph" || { log "  FAILED to remove $graph"; return 1; }

  # Record that the original is gone, so a later reader can tell "archived, source kept" from
  # "archived, source reclaimed" without guessing.
  tmp="$manifest.tmp.$$"
  sed 's/"originalRetained": true/"originalRetained": false/' "$manifest" > "$tmp" && mv "$tmp" "$manifest"

  log "  reclaimed $(human "$freed"): $graph"
  N_OK=$((N_OK + 1))
  TOTAL_IN=$((TOTAL_IN + freed))
  return 0
}

# --- args ---------------------------------------------------------------------------------------

if [ $# -eq 0 ]; then usage; exit 2; fi

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --reclaim) RECLAIM=1 ;;
    -*) log "$SELF: unknown option $1"; usage; exit 2 ;;
    *)  PATHS="$PATHS
$1" ;;
  esac
  shift
done

command -v zstd >/dev/null 2>&1 || {
  log "$SELF: zstd not found. It is not a macOS default — install it (brew install zstd)."
  exit 3
}

# --- run ----------------------------------------------------------------------------------------

if [ "$RECLAIM" -eq 1 ]; then
  log "$SELF: RECLAIM mode — originals will be deleted after re-verification"
else
  log "$SELF: archiving with zstd $ZSTD_FLAGS (originals kept)"
fi

# Expand args to a file list FIRST, then loop with the list redirected in. A `... | while read`
# would put the loop in a subshell, where FAILURES and the totals die on exit — and a tool that
# deletes files must not report success it cannot account for. Bash 3.2 has no lastpipe, so the
# temp file is how the counters survive.
LIST="${TMPDIR:-/tmp}/$SELF.$$.list"
trap 'rm -f "$LIST"' EXIT INT TERM
: > "$LIST"

printf '%s\n' "$PATHS" | while IFS= read -r p; do
  [ -n "$p" ] || continue
  if [ -d "$p" ]; then
    find "$p" -type f -name '*.graphml' -print
  else
    printf '%s\n' "$p"
  fi
done | sort > "$LIST"

if [ ! -s "$LIST" ]; then
  log "$SELF: no .graphml files found in the given paths."
  exit 4
fi

while IFS= read -r g; do
  [ -n "$g" ] || continue
  if ! archive_one "$g"; then
    FAILURES=$((FAILURES + 1))
    log "  -> failure on $g"
  fi
done < "$LIST"

log ""
if [ "$RECLAIM" -eq 1 ]; then
  log "$SELF: reclaimed $N_OK file(s), $(human "$TOTAL_IN") freed, $FAILURES refused/failed."
else
  log "$SELF: archived $N_OK file(s), $(human "$TOTAL_IN") -> $(human "$TOTAL_OUT"), $FAILURES failed."
  log "Restore any archive with:  zstd -d --long=31 <file>.graphml.zst"
  log "Reclaim disk once satisfied:  analysis/$SELF --reclaim <dir>"
fi

[ "$FAILURES" -eq 0 ] || exit 1
exit 0
