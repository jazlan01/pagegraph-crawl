# Graph compression — what changed, what it bought, what it costs

The `.graphml` corpus was 21.2 GiB across 15 graphs. It is now 42.1 MiB, with nothing discarded:
every graph round-trips byte-for-byte. This documents how, the measured numbers, and — at the
end, in detail — what the change breaks.

All figures below were measured on this machine against real graphs. Nothing is extrapolated;
where something was not measured it says so.

## What changed

Two pieces, in `analysis/`:

| | |
|---|---|
| `archive-graph.sh` | compresses a graph with `zstd -19 --long=31`, verifies the round-trip by SHA-256, writes a manifest. `--reclaim` deletes the original, but only after re-verifying |
| `lib/graph-source.mjs` | lets every analysis script open an archived graph directly. Scripts still take the plain `<name>.graphml` path; the `.zst` is resolved and decompressed **in memory** |

Twenty scripts and both parser libs were migrated onto the second. No output changed: `cookie-reads`
produces byte-identical JSON from a plaintext graph, from its archive, and from a restored copy.

## Size comparison

| graph | before | after | ratio |
|---|---:|---:|---:|
| delta | 7,075,801,690 | 4,225,170 | **1674.7×** |
| chegg | 6,468,158,047 | 4,416,744 | 1464.5× |
| costco | 2,633,909,841 | 5,903,729 | 446.1× |
| fidelity | 1,766,151,871 | 3,592,315 | 491.6× |
| directv | 1,645,672,031 | 5,861,295 | 280.8× |
| fidelityuk | 1,406,932,336 | 4,136,862 | 340.1× |
| walmart | 1,143,132,196 | 6,206,822 | 184.2× |
| google | 361,551,514 | 877,398 | 412.1× |
| brownforman | 141,104,116 | 866,652 | 162.8× |
| brownforman (gpc-only) | 40,273,282 | 629,255 | 64.0× |
| _px3 walmart ×2 | 77,213,784 | 7,382,183 | 10.5× |
| derived-cookie ×3 | 80,366 | 10,869 | ~7.4× |
| **total** | **22,759,981,074** | **44,109,294** | **516.0×** |

Bigger graphs compress far better. That is not a curiosity — it is the mechanism (below).

## Why it compresses this well

One edge attribute is the file. `stack trace` is **91.4%** of walmart and **99.2%** of delta; node
data is 1.6% and 0.15%. The engine stores each edge's stack as its own `std::string` with no
interning, so walmart's **110,905 stacks are only 14,013 distinct values** — 905 MB of a 1.14 GB
file is byte-identical repeats.

Gzip cannot see most of it. Stack values average 9,423 B and repeat at a **median distance of
12,331 B**, so a 32 KB window holds about three stack traces and **36.2% of all repeats are
further apart than gzip can reach**. Widening the window is the entire difference:

| codec (raw walmart) | bytes | ratio | wall clock |
|---|---:|---:|---:|
| `gzip -9` | 26,602,721 | 42.97× | 6.8 s |
| `zstd -19` | 7,292,402 | 156.8× | 9.0 s |
| **`zstd -19 --long=31`** | **6,206,822** | **184.2×** | **8.9 s** |
| `xz -9` | 6,681,752 | 171.1× | 9.2 s |

### Pruning first is counterproductive

| archived | compressed | fidelity cost |
|---|---:|---|
| raw | 6,206,822 | none |
| `prune-graph.py --max-frames 25` | 5,998,152 | 646 MB, 45% of every call frame, permanently |
| `--drop-stacks --drop-dom-edges` | 4,717,552 | all 110,905 traces + 54,268 edges destroyed |

Truncating stacks buys **3.4%** and cannot be undone. The compressor already exploits that
redundancy better than truncation does. `prune-graph.py` keeps its real job — making a graph
tractable to *analyse* — and is not part of archiving.

## Performance

Decompression itself is cheap: Node drains google's 361 MB archive in **252 ms** (~1.4 GB/s), and
the `zstd` CLI streams delta's full 7.08 GB in **1.08 s**. Opening a stream costs ~2 ms.

But analysis is measurably slower, because scripts read the graph more than once:

| google (361,551,514 B expanded) | plaintext | archive |
|---|---:|---:|
| `cookie-reads.mjs --json`, 3 runs | 0.63 / 0.63 / 0.64 s | 1.79 / 1.78 / 1.78 s |

**~2.8× slower.** `cookie-reads` opens the graph three times (a header read plus two full passes),
and each full pass re-decompresses. Reading `.zst` trades disk for CPU; on a page-cached plaintext
file that is a bad trade, on a cold multi-GB file it is likely a good one — **not measured**.

For scale: delta (7.08 GB expanded, 4.2 MB archive) runs `cookie-reads` end-to-end in **29.28 s**
at **2.48 GB peak RSS**. That RSS is the zstd decoder allocating the 2 GB window the `--long=31`
archives declare — not the graph being buffered.

## Limitations

### Tools that could not read archives — resolved

Three tools originally failed on archived graphs. All three are now dealt with:

- **`cookie-sites.mjs` and `edge-stacks.mjs` — deleted (Aug 2026).** Their problem was not
  archiving: both used `readFileSync`, so they were already failing on 7 of the 15 graphs (every
  client capture) because V8 caps a string near 512 MB. References were repointed at the streaming
  replacements that already covered them — `cookie-writes.mjs` (writes, deletes, `writeSpecs`) plus
  `cookie-reads.mjs` (read sites), and `edge-stacks-stream.mjs`.
- **`prune-graph.py` — fixed.** It now resolves and decompresses transparently, like the Node
  side. On Python 3.14+ it uses `compression.zstd` from the standard library; on older
  interpreters it pipes the `zstd` CLI, which `archive-graph.sh` already requires. Verified that
  all four input forms — stdlib zstd, an explicit `.zst` path, the CLI fallback under Python 3.9,
  and plaintext — produce byte-identical output.

Its stats line was also wrong on an archive: it divided by `os.path.getsize(input)`, the
*compressed* size, so "% of original" would have read far above 100%. It now counts the bytes the
parser actually consumes, which is right for every input form.

### Shell globs silently match nothing

`ls *.graphml` finds nothing in a reclaimed directory, and returns success. Anything scripted on
that pattern breaks quietly, including the discovery line in the cookie-analyst agent
(`ls -t analysis/runs/*/page_graph_*.graphml | head -1`). Use `*.graphml.zst` and strip the suffix.
This cannot be fixed from inside the Node code.

### `nvm use` is now required

Reading `.zst` needs Node's native zstd (**≥ 22.15**). `.nvmrc` pins 24, but this machine's default
`node` is still **20**, where it fails — with an explicit message naming the fix, but it fails.

### Memory

Peak RSS ~2.5 GB on the largest graphs, from the declared 2 GB window. Fine on 36 GB; not fine on
a small CI box. A smaller `--long` at archive time would cut this at some cost in ratio; the
existing archives are already written at 31.

### API changes that will catch callers

- **`readPageUrl` is now async.** A zstd frame cannot be `pread` from an arbitrary byte range, so
  the header must be streamed. Any external caller must `await`.
- **`existsSync` on a `.graphml` path is now wrong**, and wrong silently — it reports "no such
  file" for a graph that reads fine. Use `graphExists`.

### Restoring needs a flag

A plain `zstd -d` **refuses** these archives: `Frame requires too much memory for decoding`. Use
`zstd -d --long=31`. zstd names a flag in its error, but the number differs per file (it shrinks
the window to the input size); `--long=31` is the upper bound and always works.

### No random access

A zstd frame must be read from the start. Nothing can seek to an offset, so any tool wanting a
slice of a graph pays a full decompression to reach it. The streaming parsers were already
single-pass, so this costs nothing today — but it forecloses an indexed reader later.

### Single copy

After `--reclaim` the archive is the only copy. zstd embeds an XXH64 checksum, so corruption
surfaces as a decode error rather than silent bad data, and `--reclaim` re-verifies before
deleting — but there is no redundancy. 42 MiB is small enough to back up properly; that has not
been done.

## One thing that got better

The crawler's `-z`/`--compress` flag has always produced a `.graphml.gz` that **no analysis script
could read**. `graph-source.mjs` handles `.gz` too, so that output is now usable for the first
time — verified by running `cookie-reads` against a gzipped graph.
