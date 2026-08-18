#!/usr/bin/env python3
"""Stream-prune a PageGraph .graphml, principally by truncating stack traces.

Where the bytes actually are (measured, not assumed):

    walmart 1,090 MB    edge `stack trace`  999 MB  91.7%
    costco  2,512 MB    edge `stack trace` 2380 MB  94.8%

Everything else is rounding error by comparison -- node `source` (script text) is ~1%,
and node `text` (HTML text nodes) is ~0.1%, so stripping page text saves nothing worth
having. One attribute is the file.

Those stacks are deep: sampled over costco, a stack trace averages **73 frames / 25.8 KB**,
p90 129 frames, max 142. Meanwhile `extract-cookie-flows.mjs` reads only the first
`MAX_FRAMES = 8`. We write ~73 frames to disk and throw ~65 away at analysis time.

So the default here TRUNCATES rather than drops: keep the first N frames (default 25 --
comfortably above what analysis reads today, leaving headroom to show more call-stack
context without a re-crawl) and discard the tail. The payload stays valid JSON of the same
shape, so `frameList()` downstream keeps working unchanged.

Defaults are deliberately lossless apart from that truncation: no edges are dropped and no
other attribute is touched, so a pruned graph can be fed straight back into the analysis
pipeline. The older, more aggressive behaviour is still available behind flags:

    --drop-stacks       remove `stack trace` entirely instead of truncating
    --drop-dom-edges    drop DOM-churn edges (set/delete attribute, node create/insert/
                        remove, event listeners, structure, cross DOM)

Note --drop-dom-edges changes what analysis can see; do not use it for graphs you intend to
run the cookie pipeline over.

Usage:
    python3 prune-graph.py <in.graphml> <out.graphml> [--max-frames 25]
                           [--drop-stacks] [--drop-dom-edges]

The input may be plain, or an archive written by `archive-graph.sh` (`.graphml.zst`) or the
crawler's `-z` (`.graphml.gz`) -- pass the plain `<name>.graphml` path either way and it is
resolved to whatever is on disk, mirroring `analysis/lib/graph-source.mjs`. Decompression is
streamed, never staged to a temp file: a 4 MB archive expands to 6.6 GB.

Output is always plaintext. Pruning is an analysis-time step and the pruned graph is what you
then analyse; if you want it archived, run `archive-graph.sh` over it afterwards so it gets the
manifest and the SHA-256 round-trip proof that authorises `--reclaim` to delete anything.

Streaming via xml.sax (read) + XMLGenerator (write); constant memory (~1 element).
"""
import sys, os, json, argparse, gzip, subprocess, contextlib
import xml.sax
from xml.sax.saxutils import XMLGenerator
from xml.sax.xmlreader import AttributesImpl
from collections import Counter

# Must match archive-graph.sh's --long=31. Archives declare a 2 GB window, which is over the
# default decode budget, so without this the decoder refuses with "Frame requires too much
# memory for decoding" -- the same refusal `zstd -d` gives without --long=31.
ZSTD_WINDOW_LOG_MAX = 31


def resolve_graph_path(path):
    """Accept a graph path in whatever form it exists on disk (plain, .zst, .gz)."""
    if os.path.exists(path):
        return path
    for ext in (".zst", ".gz"):
        if os.path.exists(path + ext):
            return path + ext
    for ext in (".zst", ".gz"):
        if path.endswith(ext) and os.path.exists(path[: -len(ext)]):
            return path[: -len(ext)]
    sys.exit(f"graph not found: {path}\n"
             f"  Looked for it plain, .zst and .gz. An archived graph sits beside its "
             f".archive.json manifest.")


class _CountingReader:
    """A binary stream that records how many bytes it actually handed to the parser.

    The stats line used to divide by os.path.getsize(input). On an archive that is the
    COMPRESSED size, so "% of original" came out wildly above 100%. Counting what the parser
    consumes gives the true uncompressed input size for every input form.
    """

    def __init__(self, raw):
        self._raw = raw
        self.count = 0

    def read(self, n=-1):
        b = self._raw.read(n)
        self.count += len(b)
        return b

    def close(self):
        # xml.sax closes the source itself, so this can be a second close.
        try:
            self._raw.close()
        except Exception:
            pass


@contextlib.contextmanager
def open_graph(path):
    """Yield (resolved_path, reader) for a graph in any stored form."""
    resolved = resolve_graph_path(path)
    proc = None

    if resolved.endswith(".gz"):
        raw = gzip.open(resolved, "rb")
    elif resolved.endswith(".zst"):
        try:
            # Python 3.14+ (PEP 784). No third-party dependency.
            from compression.zstd import ZstdFile, DecompressionParameter
            raw = ZstdFile(resolved, options={
                DecompressionParameter.window_log_max: ZSTD_WINDOW_LOG_MAX})
        except ImportError:
            # Older interpreters: pipe the zstd CLI, which archive-graph.sh already requires.
            try:
                proc = subprocess.Popen(
                    ["zstd", "-dc", f"--long={ZSTD_WINDOW_LOG_MAX}", resolved],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                sys.exit(
                    f"this Python ({sys.version.split()[0]}) has no compression.zstd (needs "
                    f"3.14+) and zstd is not on PATH, so archived graphs cannot be read.\n"
                    f"  Install zstd (brew install zstd) or run with a 3.14+ interpreter.")
            raw = proc.stdout
    else:
        raw = open(resolved, "rb")

    reader = _CountingReader(raw)
    try:
        yield resolved, reader
    finally:
        reader.close()
        if proc is not None:
            rc = proc.wait()
            err = (proc.stderr.read().decode("utf-8", "replace").strip()
                   if proc.stderr else "")
            if proc.stderr:
                proc.stderr.close()
            # SIGPIPE (-13) is our own doing: aborting the parse early closes the pipe under
            # zstd. Ignore that. Any OTHER non-zero exit is a real decompression failure, and
            # is reported even when the parse also raised -- because it is the *cause*. A
            # corrupt archive otherwise surfaces only as "no element found", which says
            # nothing about what actually went wrong.
            if rc not in (0, -13):
                sys.exit(f"zstd failed decompressing {resolved} (exit {rc})"
                         + (f":\n  {err}" if err else ""))

DROP_EDGE_TYPES = {
    "set attribute", "delete attribute",
    "create node", "insert node", "remove node",
    "add event listener", "remove event listener", "event listener",
    "structure", "cross DOM",
}


def truncate_stack(raw, max_frames):
    """Keep the first `max_frames` frames of a DevTools Runtime.StackTrace, walking the
    `parent` chain in order, then cut the chain. Returns (text, frames_before, frames_after).

    The shape is preserved because downstream parses it as JSON; a truncated stack must
    still look like a stack, not like a string. Unparseable input is returned untouched --
    guessing at the structure of something we cannot read would be worse than keeping it.
    """
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return raw, 0, 0
    if not isinstance(obj, dict):
        return raw, 0, 0

    before = 0
    cur = obj
    while isinstance(cur, dict):
        before += len(cur.get("callFrames") or [])
        cur = cur.get("parent")

    remaining = max_frames
    after = 0
    cur = obj
    while isinstance(cur, dict):
        frames = cur.get("callFrames") or []
        if len(frames) >= remaining:
            cur["callFrames"] = frames[:remaining]
            after += remaining
            cur.pop("parent", None)      # nothing deeper survives
            break
        remaining -= len(frames)
        after += len(frames)
        parent = cur.get("parent")
        if not isinstance(parent, dict):
            break
        cur = parent

    return json.dumps(obj, separators=(",", ":")), before, after


class Pruner(xml.sax.ContentHandler):
    def __init__(self, out, max_frames=25, drop_stacks=False, drop_dom_edges=False):
        self.gen = XMLGenerator(out, encoding="utf-8", short_empty_elements=False)
        self.max_frames = max_frames
        self.drop_stacks = drop_stacks
        self.drop_dom_edges = drop_dom_edges

        # Key ids are assigned per engine build and are NOT stable -- resolve by attr.name
        # from the <key> declarations rather than hardcoding d43/d10.
        self.stack_key = None
        self.etype_key = None

        self.buf = None          # buffered events while inside a node/edge
        self.is_edge = False
        self.etype = None
        self.skip_depth = 0      # >0 while inside a stack-trace <data> being dropped
        self.in_data_key = None
        self._tbuf = None        # accumulates <data> text (SAX may split it)

        self.kept_e = Counter(); self.dropped_e = Counter()
        self.nodes = 0
        self.stacks_stripped = 0; self.stacks_truncated = 0
        self.frames_in = 0; self.frames_out = 0

    def startDocument(self): self.gen.startDocument()
    def endDocument(self): self.gen.endDocument()

    def startElement(self, name, attrs):
        if self.skip_depth:
            self.skip_depth += 1; return

        if name == "key" and self.buf is None:
            kid, kfor, kname = attrs.get("id"), attrs.get("for"), attrs.get("attr.name")
            if kfor == "edge" and kname == "stack trace": self.stack_key = kid
            if kfor == "edge" and kname == "edge type":   self.etype_key = kid

        if self.buf is None and name in ("node", "edge"):
            self.buf = []; self.is_edge = (name == "edge"); self.etype = None
            self.buf.append(("s", name, dict(attrs))); return

        if self.buf is not None:
            if name == "data" and attrs.get("key") == self.stack_key:
                if self.drop_stacks:
                    self.skip_depth = 1; self.stacks_stripped += 1; return
                self.in_data_key = self.stack_key
                self._tbuf = ""
                self.buf.append(("s", name, dict(attrs))); return
            if name == "data":
                self.in_data_key = attrs.get("key")
                if self.in_data_key == self.etype_key: self._tbuf = ""
            self.buf.append(("s", name, dict(attrs))); return

        self.gen.startElement(name, attrs)

    def characters(self, content):
        if self.skip_depth: return
        if self.buf is not None:
            # Text inside a tracked <data> is accumulated and re-emitted once at
            # endElement; everything else passes through as-is.
            if self.in_data_key in (self.stack_key, self.etype_key) and self._tbuf is not None:
                self._tbuf += content
                if self.in_data_key == self.stack_key:
                    return
            self.buf.append(("c", content))
        else:
            self.gen.characters(content)

    def endElement(self, name):
        if self.skip_depth:
            self.skip_depth -= 1; return

        if self.buf is not None:
            if name == "data":
                if self.in_data_key == self.stack_key and self._tbuf is not None:
                    text, before, after = truncate_stack(self._tbuf, self.max_frames)
                    self.frames_in += before; self.frames_out += after
                    if after < before: self.stacks_truncated += 1
                    self.buf.append(("c", text))
                elif self.in_data_key == self.etype_key:
                    self.etype = self._tbuf
                self._tbuf = None
                self.in_data_key = None
            self.buf.append(("e", name))

            if name in ("node", "edge"):
                if self.is_edge:
                    if self.drop_dom_edges and self.etype in DROP_EDGE_TYPES:
                        self.dropped_e[self.etype] += 1
                    else:
                        self.kept_e[self.etype] += 1; self._flush(self.buf)
                else:
                    self.nodes += 1; self._flush(self.buf)
                self.buf = None
            return

        self.gen.endElement(name)

    def _flush(self, evs):
        g = self.gen
        for e in evs:
            if e[0] == "s": g.startElement(e[1], AttributesImpl(e[2]))
            elif e[0] == "c": g.characters(e[1])
            else: g.endElement(e[1])


def mb(x): return f"{x/1e6:,.1f} MB"


def main():
    ap = argparse.ArgumentParser(description="Truncate stack traces in a PageGraph graphml.")
    ap.add_argument("input"); ap.add_argument("output")
    ap.add_argument("--max-frames", type=int, default=25,
                    help="stack frames to keep per trace (default 25)")
    ap.add_argument("--drop-stacks", action="store_true",
                    help="remove stack traces entirely instead of truncating")
    ap.add_argument("--drop-dom-edges", action="store_true",
                    help="also drop DOM-churn edges (lossy for the cookie pipeline)")
    a = ap.parse_args()

    with open(a.output, "w", encoding="utf-8") as fh:
        h = Pruner(fh, a.max_frames, a.drop_stacks, a.drop_dom_edges)
        p = xml.sax.make_parser()
        p.setContentHandler(h)
        with open_graph(a.input) as (resolved, reader):
            p.parse(reader)
            si = reader.count

    so = os.path.getsize(a.output)
    compressed = resolved.endswith((".zst", ".gz"))
    print(f"in : {mb(si)}  {resolved}"
          + (f"  (decompressed; {mb(os.path.getsize(resolved))} on disk)" if compressed else ""))
    print(f"out: {mb(so)}  {a.output}   ({100*so/si:.1f}% of original, -{mb(si-so)})"
          if si else f"out: {mb(so)}  {a.output}")
    if h.stack_key is None:
        print("WARNING: no edge attribute named 'stack trace' found -- nothing truncated")
    print(f"nodes kept: {h.nodes:,}   edges kept: {sum(h.kept_e.values()):,}")
    if a.drop_stacks:
        print(f"stack traces removed: {h.stacks_stripped:,}")
    else:
        print(f"stack traces truncated: {h.stacks_truncated:,}  "
              f"frames {h.frames_in:,} -> {h.frames_out:,} "
              f"({100*h.frames_out/h.frames_in:.1f}% kept)" if h.frames_in else
              "stack traces truncated: 0")
    if h.dropped_e:
        print("edges dropped:")
        for t, c in h.dropped_e.most_common(): print(f"  {c:>9,}  {t}")


if __name__ == "__main__":
    main()
