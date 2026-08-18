// graph-source.mjs — open a PageGraph graphml whatever form it is stored in.
//
// Graphs are archived by `analysis/archive-graph.sh` (zstd -19 --long=31, 180-1600x) and the
// plaintext original deleted. This exists so that costs the analysis tools nothing: ask for
// `foo.graphml` and get a utf8 stream, whether what is on disk is `foo.graphml`, `foo.graphml.zst`
// or `foo.graphml.gz`.
//
// Decompression is IN MEMORY. A 4 MB archive expands to 6.6 GB, so materialising it to a temp file
// to read it once would undo the point of archiving. The decoder is composed straight onto the
// existing carry-buffer parsers, which already stream — peak memory is the parser's ~1 MB carry
// buffer plus a chunk, not the size of the graph.
//
// Nothing here implements decompression or stream plumbing: `zlib.createZstdDecompress` is the
// Node builtin, and `stream.compose` does the wiring and the error propagation.
//
// TWO THINGS THAT WILL BITE, both verified against a real archive rather than assumed:
//
//  1. ZSTD_d_windowLogMax is mandatory. The archives use a 2 GB window (--long=31), over zlib's
//     default 128 MiB decode budget, and without it the decoder fails with "Frame requires too
//     much memory for decoding" — the same refusal the zstd CLI gives without --long=31.
//  2. Node needs native zstd (>= 22.15 / >= 23.8). `.nvmrc` pins 24; run `nvm use` first. Node 20
//     is still this machine's default and fails with the clear message below.

import { createReadStream, existsSync } from "node:fs";
import { compose } from "node:stream";
import zlib from "node:zlib";

// Must match archive-graph.sh's --long=31.
const ZSTD_OPTS = { params: { [zlib.constants.ZSTD_d_windowLogMax ?? 100]: 31 } };

const COMPRESSED = [".zst", ".gz"];

export const isGraphPath = (p) => /\.graphml(\.zst|\.gz)?$/.test(p);

// `foo.graphml` -> `foo`; `foo.pruned.graphml.zst` -> `foo`. Sidecars (.cookies.json,
// .bodies.ndjson, ...) hang off this base, so it must strip the compression suffix too or every
// sidecar lookup silently misses once a graph is archived.
export const graphBase = (p) =>
  p.replace(/\.(zst|gz)$/, "").replace(/(\.pruned)?\.graphml$/, "");

// Callers, agent instructions and skills all still say `<name>.graphml`. Rather than rewrite every
// one, resolve to whichever form is actually on disk.
export const resolveGraphPath = (p) => {
  if (existsSync(p)) return p;
  for (const ext of COMPRESSED) if (existsSync(p + ext)) return p + ext;
  for (const ext of COMPRESSED) {
    if (p.endsWith(ext) && existsSync(p.slice(0, -ext.length))) return p.slice(0, -ext.length);
  }
  throw new Error(
    `graph not found: ${p}\n` +
    `  Looked for it plain, .zst and .gz. An archived graph sits beside its .archive.json manifest.`
  );
};

// True if the graph is readable in ANY form. Callers must not use bare existsSync on a .graphml
// path: once archived and reclaimed, the plaintext name no longer exists on disk.
export const graphExists = (p) => {
  try { resolveGraphPath(p); return true; } catch { return false; }
};

const decoderFor = (path) => {
  if (path.endsWith(".gz")) return zlib.createGunzip();
  if (!path.endsWith(".zst")) return null;
  if (typeof zlib.createZstdDecompress !== "function") {
    throw new Error(
      `this Node (${process.version}) has no zstd support, so archived graphs cannot be read.\n` +
      `  Run \`nvm use\` in the repo root (.nvmrc pins Node 24), then re-run.`
    );
  }
  return zlib.createZstdDecompress(ZSTD_OPTS);
};

// A utf8 Readable of the graph's XML. Drop-in for createReadStream(path, { encoding: "utf8" }).
export const graphStream = (p) => {
  const path = resolveGraphPath(p);
  const decoder = decoderFor(path);
  if (!decoder) return createReadStream(path, { encoding: "utf8" });
  const s = compose(createReadStream(path), decoder);
  s.setEncoding("utf8");
  return s;
};

// The graphml header carries <url>…</url> near the top; stop as soon as it is found. On the delta
// archive that decompresses a few hundred KB, not 6.6 GB, and returns in ~4 ms.
//
// ASYNC BY NECESSITY: the old sync openSync/readSync could pread a plaintext header, but a zstd
// frame cannot be decoded from an arbitrary byte range. Callers are ESM and use top-level await.
export const readPageUrl = async (p, maxBytes = 262144) => {
  const st = graphStream(p);
  let s = "";
  try {
    for await (const chunk of st) {
      s += chunk;
      const m = s.match(/<url>([^<]*)<\/url>/);
      if (m) return m[1];
      if (s.length >= maxBytes) break;
    }
  } finally {
    st.destroy();
  }
  return (s.match(/<url>([^<]*)<\/url>/) || [])[1] ?? null;
};
