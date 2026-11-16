# Native HTTP response-limit benchmark

This experiment measures how much client allocation and response reading are
needed to reject an oversized local API response. The baseline receives the
response before applying the caller's 1 MiB limit. The candidate passes that
limit into the transport so it can reject the response while receiving it.

The experiment is a standalone Rust program using only the standard library.
It opens an ephemeral loopback server on `127.0.0.1`, without contacting a
device or an external service. It does not load MagicNet configuration,
subscriptions, or credentials, and it is not linked into production builds.

## Fixed input and comparison

Both variants request a fixture that offers an 8 MiB body, with a 1 MiB caller
limit and a five-second request timeout. Each framing case has one discarded
warm-up followed by seven measured samples by default.

| Setting | Value |
| --- | --- |
| Offered response body | 8,388,608 bytes |
| Caller body limit | 1,048,576 bytes |
| Content-Length case | Declared body length of 8 MiB; 63-byte response header |
| Close-delimited case | No declared body length; 38-byte response header |
| Server body buffer | Reusable 8 KiB stack block |
| Expected outcome | Both variants return the caller-limit error |
| Compiler flags | `--edition=2024 -C opt-level=3` |
| Candidate-only configuration | `--cfg magicnet_candidate` |

The baseline is the native HTTP module from a specified local Git commit before
the caller-limit parameter was added. Its harness applies the original WebUI
limit check after the transport returns. The candidate is the current working
tree's `crates/magicnet-cli/src/local_http.rs`, including any uncommitted
changes to that file.

## Reproduce

Run from the source repository root, which contains `crates/` and
`scripts/`. The required tools are Python 3.10 or later, Git, and a Rust
compiler supporting edition 2024. No Cargo dependencies or network fetches are
needed. The selected baseline commit must already exist in local Git history.

```sh
python3 scripts/benchmarks/http-response-limit/run.py \
  --baseline b6f3a37f \
  --iterations 7 \
  --output target/http-response-limit-results
```

The output directory must be new. This preserves previous evidence if the
command is repeated. Use another output directory for a reversed-order run:

```sh
python3 scripts/benchmarks/http-response-limit/run.py \
  --baseline b6f3a37f \
  --iterations 7 \
  --order after-first \
  --output target/http-response-limit-results-reversed
```

`--baseline` accepts another compatible pre-change commit. The runner resolves
it to its full commit ID, snapshots both source versions, and checks their API
shapes before compilation. It rejects unsupported source layouts instead of
silently omitting instrumentation. `--rustc` can select a compiler executable;
`--iterations` accepts 1 through 100.

The runner prepares source copies and compiled programs in a system temporary
directory. It adds the same response-read counter immediately before the EOF
branch in each copy. Production source is untouched. The temporary directory
is removed when the run ends, including ordinary failures. The only persistent
outputs are the four evidence files below; no compiled binary is added to the
repository.

| Output | Contents |
| --- | --- |
| `before.jsonl` | Every measured baseline sample |
| `after.jsonl` | Every measured candidate sample |
| `summary.json` | Sample count and median, minimum, and maximum per variant and framing case |
| `manifest.json` | Git identities, original and instrumented source hashes, harness and runner hashes, compiler details, host platform, order, and result hashes |

The manifest records whether the candidate source matches its recorded HEAD
commit. If it does not, the SHA-256 identifies the measured source, but that
commit alone cannot reconstruct it. Commit the candidate or retain its patch
when publishing results. The runner records platform details without a
hostname or developer workspace path; temporary paths in compiler warnings are
replaced by a placeholder.

## Metric definitions

Allocation counters are active only on the client main thread during the
request. The loopback server runs on a separate, untracked thread, and request
setup objects are created before tracking begins. A custom allocator observes
successful allocations, reallocations, and deallocations while forwarding them
to Rust's system allocator.

| JSON field | Meaning |
| --- | --- |
| `peak_live_heap_bytes` | Highest sum of requested allocation sizes still live during the tracked request. This includes request and response buffers and the returned error. |
| `total_requested_heap_bytes` | Sum of requested sizes for allocations and successful reallocations during the request. A reallocation contributes its full new size, not only its growth. |
| `allocation_calls` | Count of successful allocation, zeroed-allocation, and reallocation calls. Deallocations are not counted as calls in this field. |
| `live_heap_bytes_at_return` | Requested allocation bytes still live when the request returns, before the result is dropped. |
| `client_socket_read_bytes` | Bytes actually returned by the client's response reads, including HTTP headers. |
| `client_read_calls` | Successful response-read calls, including a zero-byte EOF read if one is needed. |
| `elapsed_us` | Microseconds from starting the instrumented client request to the expected rejection. It excludes joining the server thread afterward. |
| `server_write_accepted_body_bytes` | Body bytes accepted by the server socket's write calls. It excludes headers and can exceed bytes consumed by the client. |
| `server_completed_body` | Whether the server's writes accepted the complete offered body before the connection closed. |
| `response_body_offered_bytes` | Intended fixture body size; it does not imply the client read that many bytes. |
| `caller_limit_bytes` | Maximum response body size accepted by the caller. |
| `outcome` | Must be `caller_limit_rejected` for every reported sample. |

The heap counters measure requested allocation sizes rather than allocator
arena size or physical memory. They omit allocator metadata, transient
allocator-internal copies during reallocation, stack memory, kernel socket
buffers, and other threads. These values are not process RSS or PSS, Go heap
usage, idle resident memory, or Android service memory.

Socket reads and accepted writes describe different events. Kernel buffering
can let the server enqueue body data that the client never reads. A
Content-Length response can also deliver some body data in the same read as
its headers, so rejecting its declared length does not imply zero body bytes
were received.

## Validate and interpret a run

The runner checks sample counts, the expected error, numeric field consistency,
and fixture byte counts before writing results. The baseline must consume the
offered body. The close-delimited candidate must stop after the caller budget
plus one overflow byte. The Content-Length candidate must stop when it has
parsed the oversized declaration, allowing header fragmentation and body bytes
already present in that read. These checks validate the experiment's scope;
they are not performance thresholds.

Report each result with its manifest, framing case, number of samples, and
observed range. Keep the same compiler and flags for both variants. Reversed
execution order helps check whether an unexpected timing difference follows
the code or the order. Neither seven samples nor reversing order establishes
a statistical guarantee.

Elapsed time includes allocator and read-counter bookkeeping, connection
setup, fixture accept scheduling, and operating-system scheduling. The
fixture polls for an accepted connection at one-millisecond intervals, which
can be visible in short samples. Timing here measures the work needed to
reject an oversized local response; it is not a measure of valid download
throughput or Internet speed.

This experiment does not establish normal-request latency, routing behavior,
battery use, active TUN throughput, or whole-device memory savings. Existing
HTTP framing, first-line, timeout, and caller-limit regression tests remain
separate correctness checks. Benchmark success does not replace those tests.
