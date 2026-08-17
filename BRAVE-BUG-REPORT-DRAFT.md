# DRAFT — not sent anywhere

Report for Brave. Review and edit before submitting; nothing here has been
disclosed. Suggested channel: Brave's HackerOne programme, or a GitHub issue on
`brave/brave-browser` if you and Brave agree it is not a security issue (see
Impact — it is arguably not, and mislabelling it would waste their triage time).

---

# V8 heap corruption in PageGraph builtin tracking: stale `Tagged<Object>` returned to JS after GC

## Summary

When PageGraph's V8 builtin tracking is compiled in, the patched `BUILTIN` macro
passes the builtin's raw, unrooted result to `ReportBuiltinCallAndResponse`,
which allocates freely while serializing arguments. If a GC runs during that
window the result object moves, and the macro then returns the **stale address**
to generated JavaScript.

The corrupted value behaves as a heap object with a garbage map. It does not
fault where the damage occurs — it detonates later, during ordinary property
access in unrelated script, which makes it very hard to attribute.

## Affected component

- `brave/chromium_src/v8/src/builtins/builtins-utils.h` — the `BUILTIN` macro override
- `brave/chromium_src/v8/src/builtins/builtins.cc` — `ReportBuiltinCallAndResponse`

Guarded by `BUILDFLAG(ENABLE_BRAVE_PAGE_GRAPH_WEBAPI_PROBES)`.

Tracked builtins are `Console`, `Date`, `Json` (`IsBuiltinTrackedInPageGraph`),
so `JSON.stringify`, `JSON.parse`, `Date` methods and `console.*` are all
affected — trivially reachable from any page.

## Impact

**Not remotely exploitable against stable Brave users**, and it should not be
described that way:

- `enable_brave_page_graph` defaults true on Windows/macOS/Linux desktop, so the
  base feature is compiled into shipping desktop builds.
- `enable_brave_page_graph_webapi_probes` — which gates the affected code — is
  `enable_brave_page_graph && (!is_official_build || brave_channel == "dev" ||
  brave_channel == "nightly")`. So the vulnerable code is **absent from official
  stable builds** and present in dev/nightly and all non-official builds.
- The runtime feature `kPageGraph` is `FEATURE_DISABLED_BY_DEFAULT`, so it also
  requires `--enable-features=PageGraph` (or a field trial).

Realistic exposure is therefore: a **dev/nightly desktop user running
`--enable-features=PageGraph`** gets attacker-influenced memory corruption
reachable from ordinary web content. Everyone else is unaffected.

### Exploitability — what we measured

We probed this deliberately rather than speculating. A page repeatedly calls a
tracked builtin (`JSON.stringify`) under allocation churn, with
`--js-flags=--stress-compaction` so every GC relocates objects, and checks after
each call whether the returned value is *usable but wrong* — wrong `typeof`,
corrupted contents, implausible length, failed round-trip — as opposed to simply
fatal. Findings are streamed to the console per-iteration, because a summary at
the end is lost when the renderer aborts.

Result across three runs against a vulnerable build:

- **No survivable type confusion was observed.** 6,000+ tracked-builtin calls
  produced zero type or content anomalies, then the renderer died
  (`Received signal 10`, SIGBUS). A second variant died with SIGABRT.
- One apparent anomaly in an earlier probe **did not reproduce** and its output
  was self-inconsistent; we treat it as a probe artifact, not evidence.

So on our evidence the corrupted value faults at the point of use rather than
becoming an attacker-usable object. We could not demonstrate a memory-disclosure
primitive, and therefore have not demonstrated exploitability.

We would caution against reading that as "not exploitable". The scope of the test
was narrow: one builtin, one workload, no heap grooming, and no attempt to place
chosen data at the vacated address. A stale reference into memory that the
allocator can hand back out is inherently dangerous, and a dedicated attempt at
controlling the reoccupant may reach a different conclusion. We are reporting the
primitive and our measurements; the exploitability judgement is Brave's to make.

Deliberately not included: we did not build an exploit chain. The escalation
techniques involved are generic to V8 rather than specific to this bug.

## Root cause

`BUILTIN` (upstream `builtins-utils.h`):

```cpp
Tagged<Object> result(Builtin_Impl_##name(args, isolate));      // raw, unrooted
if (V8_UNLIKELY(IsBuiltinTrackedInPageGraph(#name)) &&
    V8_UNLIKELY(isolate->page_graph_delegate())) {
  ReportBuiltinCallAndResponse(isolate, #name, args, result);   // allocates -> may GC
}
return BUILTIN_CONVERT_RESULT(result);                          // stale if GC moved it
```

`ReportBuiltinCallAndResponse` (upstream `builtins.cc`):

```cpp
void ReportBuiltinCallAndResponse(Isolate* isolate,
                                  const char* builtin_name,
                                  const BuiltinArguments& builtin_args,
                                  const Tagged<Object>& builtin_result) {
  HandleScope scope(isolate);
  std::vector<std::string> args;
  for (int arg_idx = 1; arg_idx < builtin_args.length(); ++arg_idx) {
    args.push_back(ToPageGraphArg(isolate, builtin_args.at(arg_idx)));  // allocates
  }

  std::optional<std::string> result;
  if (builtin_result.ptr() && !IsUndefined(builtin_result)) {           // read AFTER
    result = ToPageGraphArg(isolate, Handle<Object>(builtin_result, isolate));
  }
  ...
}
```

`ToPageGraphArg` reaches `Object::NoSideEffectsToMaybeString`, which builds
strings and can trigger a GC. There are two distinct defects:

1. **Read after move, inside the function.** `builtin_result` is dereferenced
   after the argument loop has already allocated.
2. **Stale value returned to JS, in the macro.** Even if (1) is fixed by rooting
   locally, the GC updates the local handle while the macro's own `result`
   variable keeps the old address — and that is what is handed back to generated
   code. This is the more serious half, because the corruption escapes into the
   JS heap rather than merely faulting here.

Arguments and receiver come from `BuiltinArguments` and are already rooted in the
frame, so they are unaffected.

## Symptom

Faults far from the cause, in unrelated script:

```
EXC_BAD_ACCESS (code=2, address=0x932ffea030f)   // garbage, not a heap address
v8::internal::Map::instance_type()
v8::internal::InstanceTypeChecker::IsJSObject
v8::internal::IsJSObjectMap
v8::internal::IC::ShouldRecomputeHandler          ic.cc:267
v8::internal::IC::UpdateState                     ic.cc:301
v8::internal::Runtime_LoadIC_Miss                 ic.cc:3218
[~30 JIT frames of ordinary JS]
```

Chromium's own dump reports `Received signal 10 BUS_ADRALN`. No PageGraph frame
appears at the fault site.

## Reproduction status — read this before triaging

**The defect is present in current `brave-core` master.** Verified against the
live source: `builtin_result` is still `const Tagged<Object>&`, it is still
rooted into a `Handle` only *after* the `ToPageGraphArg` argument loop, and
there is still no write-back to the caller.

**We could NOT reproduce a crash on shipping Brave Nightly.** Tested against
Nightly 151.1.95.27 with `--enable-features=PageGraph`, a throwaway profile, and
a page issuing a high volume of `JSON.stringify` calls with a deliberately small
live heap:

| Configuration | Result |
|---|---|
| Nightly, PageGraph on | survived 1,333,500 iterations |
| Nightly, PageGraph off | survived 186,532,000 iterations |
| Nightly, PageGraph on, `--js-flags=--stress-compaction` | survived 517,000 iterations |

PageGraph was confirmed active in those runs (a control crawl produced a 28 KB
graph, and the ~140x throughput drop with PageGraph on shows every builtin call
is being routed through argument serialization).

**It reproduces deterministically on our instrumented fork**, which adds
substantial per-edge allocation during recording (a JS stack capture on every
graph edge, plus event logging). Our working hypothesis for the gap is that this
extra allocation greatly raises the chance a GC lands inside the vulnerable
window; stock Brave allocates far less per builtin call. We have not proven that
mechanism.

So the honest characterisation is: **a real memory-safety defect in current code,
which we have shown is triggerable under heavy additional allocation pressure but
have NOT shown is reachable in a shipping configuration.** We are not claiming
Brave users are at risk. We think it is worth fixing on its own terms — the
pattern is unsafe regardless of how hard it currently is to hit, and the
allocation profile around it could change at any time.

An earlier apparent crash of stock Nightly turned out to be OOM caused by our own
test page retaining a large heap during in-memory graph serialization, not this
bug. We mention it so nobody re-derives it and draws the wrong conclusion.

## Reproduction (on a fork/build where it triggers)

Requires a build with `enable_brave_page_graph_webapi_probes` (any non-official
build, or dev/nightly).

```
PAGEGRAPH_OUT_DIR=/tmp/pg "<brave>" \
  --enable-features=PageGraph --no-sandbox --disable-breakpad \
  --disable-site-isolation-trials --no-first-run --user-data-dir=/tmp/pgprofile \
  https://www.nytimes.com
```

Renderer dies within ~10s. Any JSON/Date/console-heavy page under memory
pressure should do; nytimes.com was simply reliable for us.

Make it deterministic with `--js-flags="--stress-compaction"`, which forces
objects to move on every GC.

## Evidence that this is the cause

Single-variable A/B on the same site with the same stress flag:

| Build | `--stress-compaction` result |
|---|---|
| With the fix below | full graph, 769 MB, no crash |
| Without it, nothing else changed | renderer dies |

Without stress flags, nytimes.com went from a 1.7 MB recovered partial to a full
2.3 GB graph (16,517 nodes / 141,344 edges). cnn.com, walmart.com, pgatour.com,
directv.com and nike.com also complete.

## Proposed fix

Make the result an in/out parameter and write the possibly-relocated address back
before the `HandleScope` is destroyed, so the macro returns the updated pointer.

`builtins-utils.h`:

```diff
-      ReportBuiltinCallAndResponse(isolate, #name, args, result);
+      ReportBuiltinCallAndResponse(isolate, #name, args, &result);
```

`builtins.cc`:

```diff
-                                  const Tagged<Object>& builtin_result) {
+                                  Tagged<Object>* builtin_result) {
   HandleScope scope(isolate);
+
+  const bool has_result =
+      builtin_result->ptr() && !IsUndefined(*builtin_result);
+  Handle<Object> result_handle =
+      has_result ? Handle<Object>(*builtin_result, isolate) : Handle<Object>();
+
   std::vector<std::string> args;
   for (int arg_idx = 1; arg_idx < builtin_args.length(); ++arg_idx) {
     args.push_back(ToPageGraphArg(isolate, builtin_args.at(arg_idx)));
   }
 
   std::optional<std::string> result;
-  if (builtin_result.ptr() && !IsUndefined(builtin_result)) {
-    result = ToPageGraphArg(isolate, Handle<Object>(builtin_result, isolate));
+  if (has_result) {
+    result = ToPageGraphArg(isolate, result_handle);
   }
   ...
+  // Hand the possibly-relocated address back to the BUILTIN macro. Must happen
+  // before `scope` is destroyed.
+  if (has_result) {
+    *builtin_result = *result_handle;
+  }
 }
```

The result is rooted **before** anything allocates, and the relocated address is
written back through the pointer.

## Related, same class, possibly worth auditing together

`brave/chromium_src/v8/src/inspector/value-mirror.cc`, `SerializeValue`, passes
its argument to `ValueMirror::getProperties` via `value.As<Object>()` with no
`IsObject()` check. A non-object makes V8 walk a bogus object layout; we observed
`BUS_ADRALN` inside `KeyAccumulator::CollectOwnElementIndices` while serializing
`XMLHttpRequest.send` arguments on cnn.com. Adding the type guard fixed that site.

## Provenance note

Established with `git log -S`: the unrooted `const Tagged<Object>& builtin_result`
parameter originates upstream (`8093d2c12ba`, "[v8] Object instances must be
tagged"). A partial mitigation in our local research branch rooted the value into
a local handle, which fixed the in-function read but not the value returned to
JS; the fix above addresses both.

## Credit

<your name / Vault JS>
