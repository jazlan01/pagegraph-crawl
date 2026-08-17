#!/usr/bin/env bash
# run-consent-matrix.sh — crawl every client site under each consent state.
#
#   analysis/run-consent-matrix.sh <out-root> [site ...]
#
# WHY: the 2026-08-02 audit was crawled with Consent-O-Matic set to accept-all, but that was never
# recorded in the artifacts, so the consent state of any given run had to be recalled rather than
# read. A finding of the form "the site ignored the visitor's choice" is only interpretable against
# a KNOWN state, and only meaningful next to the other states — a site that contacts the same ad
# hosts whether you accept or reject is telling you the choice changed nothing. This runs all three
# states so that comparison exists.
#
# The three states, and what each is for:
#   gpc-only     no extension. Brave still asserts Global Privacy Control, so this is the
#                browser's own signal with no banner interaction — the CCPA/CPRA case.
#   accept-all   Consent-O-Matic clicking accept. Upper bound on what the site will load.
#   reject-all   Consent-O-Matic clicking reject (upstream's own defaults). The comparison case.
#
# Graphs are pruned immediately after each crawl. Verified before relying on it: the default prune
# only truncates stack traces to 25 frames, and `timestamp`, `request id`, `key`, `value`,
# `edge type` and `script position` all survive with identical counts — so consent-write ordering
# and request provenance are intact. A full pass is ~21 GB unpruned; pruning is what makes three
# passes fit in the free space.
#
# Each run's state is stamped into its own .crawl-status.json (consentConfig), so the output is
# self-describing even if this script's directory layout is later rearranged.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${1:?usage: run-consent-matrix.sh <out-root> [site ...]}"
shift || true

BRAVE="${PAGEGRAPH_BRAVE:-$HOME/brave/src/out/Release_arm64/Brave Browser.app/Contents/MacOS/Brave Browser}"
ACCEPT_EXT="${ACCEPT_EXT:-$HOME/Consent-O-Matic/build}"
REJECT_EXT="${REJECT_EXT:-$HOME/Consent-O-Matic-reject/build}"
DWELL="${DWELL:-40}"     # the extension has to find and click the banner before the dwell ends

# macOS ships bash 3.2, which has no associative arrays — a `declare -A` lookup here fails with
# "unbound variable" under `set -u`. A case statement is portable and needs no newer shell.
SITES_D="brownforman chegg costco delta directv fidelity fidelityuk walmart"
url_for() {
  case "$1" in
    brownforman) echo "https://www.brown-forman.com/" ;;
    chegg)       echo "https://www.chegg.com/" ;;
    costco)      echo "https://www.costco.com/" ;;
    delta)       echo "https://www.delta.com/" ;;
    directv)     echo "https://www.directv.com/" ;;
    fidelity)    echo "https://www.fidelity.com/" ;;
    fidelityuk)  echo "https://www.fidelity.co.uk/" ;;
    walmart)     echo "https://www.walmart.com/" ;;
    *)           echo "" ;;
  esac
}
if [ "$#" -gt 0 ]; then SITES_D="$*"; fi

for tool in "$BRAVE"; do
  [ -x "$tool" ] || { echo "missing browser: $tool" >&2; exit 1; }
done
for ext in "$ACCEPT_EXT" "$REJECT_EXT"; do
  [ -d "$ext" ] || { echo "missing extension build: $ext" >&2; exit 1; }
done

echo "browser : $BRAVE"
echo "accept  : $ACCEPT_EXT"
echo "reject  : $REJECT_EXT"
echo "dwell   : ${DWELL}s"
echo

for state in gpc-only accept-all reject-all; do
  # bash 3.2 treats "${EMPTY[@]}" as unbound under `set -u`, so the expansion below is guarded
  # with ${arr[@]+...}. Without it the no-extension state — the baseline the whole comparison
  # rests on — is the one state that fails.
  case "$state" in
    gpc-only)   EXT_ARGS=() ;;
    accept-all) EXT_ARGS=(--extensions-path "$ACCEPT_EXT") ;;
    reject-all) EXT_ARGS=(--extensions-path "$REJECT_EXT") ;;
  esac

  for site in $SITES_D; do
    url="$(url_for "$site")"
    [ -n "$url" ] || { echo "!! no URL for site '$site', skipping" >&2; continue; }
    dir="$OUT_ROOT/$state/$site"
    # The output dir must EXIST before the crawl: the patched build streams the graphml into it
    # from the renderer, and a missing dir yields a 0-byte graph with exit 0 (a false success).
    mkdir -p "$dir"

    echo "=== $state / $site"
    ( cd "$REPO" && npm run crawl -- \
        --shields down -i -t "$DWELL" --save-cookies \
        ${EXT_ARGS[@]+"${EXT_ARGS[@]}"} \
        -u "$url" -o "$dir" -b "$BRAVE" ) \
      >"$dir/crawl.log" 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
      echo "    crawl exited $rc — see $dir/crawl.log" >&2
    fi

    # Prune in place. Keep going on failure: a missing prune costs disk, not correctness, and
    # aborting the matrix over it would waste the runs already done.
    for g in "$dir"/*.graphml; do
      [ -e "$g" ] || continue
      if python3 "$REPO/analysis/prune-graph.py" "$g" "$g.pruned" >>"$dir/crawl.log" 2>&1; then
        mv "$g.pruned" "$g"
      else
        echo "    prune failed for $g" >&2
        rm -f "$g.pruned"
      fi
    done

    sz=$(du -sh "$dir" 2>/dev/null | cut -f1)
    echo "    done — $sz   (free: $(df -h "$OUT_ROOT" | tail -1 | awk '{print $4}'))"
  done
done

echo
echo "matrix complete. Verify each run's recorded state before comparing:"
echo "  grep -h consentConfig -A3 $OUT_ROOT/*/*/*.crawl-status.json | head"
echo "A reject run whose consent cookie still shows targeting granted means the click FAILED —"
echo "that run is not a reject state and must not be compared as one."
