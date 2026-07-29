#!/usr/bin/env python3
"""Stream-prune a PageGraph .graphml.

Tier 2: strip the per-edge `stack trace` attribute (key d43) from every element,
and drop whole edges whose `edge type` (key d10) is DOM churn (set/delete
attribute, create/insert/remove node, event listeners, structure, cross DOM).
Only edges and one attribute are removed -- no nodes -- so no dangling refs.

Usage: python3 prune-graph.py <in.graphml> <out.graphml>
Streaming via xml.sax (read) + XMLGenerator (write); constant memory (~1 element).
"""
import sys, os
import xml.sax
from xml.sax.saxutils import XMLGenerator
from xml.sax.xmlreader import AttributesImpl
from collections import Counter

STACK_TRACE_KEY = "d43"          # attr.name="stack trace"
EDGE_TYPE_KEY = "d10"            # attr.name="edge type"
DROP_EDGE_TYPES = {
    "set attribute", "delete attribute",
    "create node", "insert node", "remove node",
    "add event listener", "remove event listener", "event listener",
    "structure", "cross DOM",
}

class Pruner(xml.sax.ContentHandler):
    def __init__(self, out):
        self.gen = XMLGenerator(out, encoding="utf-8", short_empty_elements=False)
        self.buf = None          # list of buffered events while inside a node/edge
        self.is_edge = False
        self.etype = None
        self.skip_depth = 0      # >0 while inside a d43 <data> we are dropping
        self.in_data_key = None
        self._tbuf = None        # accumulates edge-type text
        # stats
        self.kept_e = Counter(); self.dropped_e = Counter()
        self.nodes = 0; self.stacks_stripped = 0

    def startDocument(self): self.gen.startDocument()
    def endDocument(self): self.gen.endDocument()

    def startElement(self, name, attrs):
        if self.skip_depth:
            self.skip_depth += 1; return
        if self.buf is None and name in ("node", "edge"):
            self.buf = []; self.is_edge = (name == "edge"); self.etype = None
            self.buf.append(("s", name, dict(attrs))); return
        if self.buf is not None:
            if name == "data" and attrs.get("key") == STACK_TRACE_KEY:
                self.skip_depth = 1; self.stacks_stripped += 1; return
            if name == "data":
                self.in_data_key = attrs.get("key")
                if self.in_data_key == EDGE_TYPE_KEY: self._tbuf = ""
            self.buf.append(("s", name, dict(attrs))); return
        self.gen.startElement(name, attrs)

    def characters(self, content):
        if self.skip_depth: return
        if self.buf is not None:
            self.buf.append(("c", content))
            if self.in_data_key == EDGE_TYPE_KEY and self._tbuf is not None:
                self._tbuf += content
        else:
            self.gen.characters(content)

    def endElement(self, name):
        if self.skip_depth:
            self.skip_depth -= 1; return
        if self.buf is not None:
            if name == "data":
                if self.in_data_key == EDGE_TYPE_KEY:
                    self.etype = self._tbuf; self._tbuf = None
                self.in_data_key = None
            self.buf.append(("e", name))
            if name in ("node", "edge"):
                if self.is_edge:
                    if self.etype in DROP_EDGE_TYPES:
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
    inp, out = sys.argv[1], sys.argv[2]
    h = Pruner(open(out, "w", encoding="utf-8"))
    p = xml.sax.make_parser()
    p.setContentHandler(h)
    with open(inp, "rb") as f:
        p.parse(f)
    si, so = os.path.getsize(inp), os.path.getsize(out)
    print(f"in : {mb(si)}  {inp}")
    print(f"out: {mb(so)}  {out}   ({100*so/si:.1f}% of original, -{mb(si-so)})")
    print(f"nodes kept: {h.nodes:,}   stack-trace attrs stripped: {h.stacks_stripped:,}")
    print("edges kept:")
    for t, c in h.kept_e.most_common(): print(f"  {c:>9,}  {t}")
    print("edges dropped:")
    for t, c in h.dropped_e.most_common(): print(f"  {c:>9,}  {t}")

if __name__ == "__main__":
    main()
