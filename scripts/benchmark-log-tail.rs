//! Local microbenchmark for the CLI/MCP bounded log snapshot and last-N-lines path.
//!
//! Run from the source repository:
//!   rustc --edition=2021 -O scripts/benchmark-log-tail.rs -o /tmp/magicnet-log-bench
//!   /tmp/magicnet-log-bench
//!
//! The baseline functions were extracted by name from
//! a5617d6371fe17494fb4b4a6f655a0c8a0f7461e:
//! crates/magicnet-cli/src/mcp_server/logs.rs (read_log_snapshot and log_read).
//! The candidate functions were extracted by name from the current production
//! file. Their source is checked below so later edits cannot silently benchmark
//! a stale candidate. Both paths retain the same 1 MiB snapshot and UTF-8 rules.
//!
//! Scope: in-memory Read+Seek snapshot, UTF-8 conversion and selecting 120 lines.
//! This excludes filesystem access/path validation, redaction, stdout, networking
//! and daemon residency. Results do not estimate device-wide throughput or RSS.
//! Heap figures are peak extra allocator-requested bytes above the fixture's
//! existing allocations; they include snapshot, line index and result buffers.
//! Latency is the median of five batches of 50 calls, in microseconds per call.
//! A counting allocator is enabled for both variants. Before timing, compare
//! 233,280 cases spanning CR/LF, Unicode, malformed UTF-8 and empty/short tails.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
const MAX_LOG_READ_BYTES: u64 = 1024 * 1024;
struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
fn record(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
    CALLS.fetch_add(1, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            record(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let p = System.realloc(p, l, n);
        if !p.is_null() {
            LIVE.fetch_sub(l.size(), Ordering::Relaxed);
            record(n);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            record(l.size());
        }
        p
    }
}
#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;
fn old_snapshot(mut file: impl Read + Seek, len: u64) -> std::io::Result<String> {
    let start = len.saturating_sub(MAX_LOG_READ_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.take(len - start).read_to_end(&mut bytes)?;
    if start > 0 {
        if let Some(index) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=index);
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
fn new_snapshot(mut file: impl Read + Seek, len: u64, max_bytes: u64) -> std::io::Result<String> {
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.take(len - start).read_to_end(&mut bytes)?;
    if start > 0 {
        if let Some(index) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=index);
        }
    }
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}
fn tail_lines(text: &str, lines: usize) -> std::str::Lines<'_> {
    let bytes: usize = text
        .split_inclusive('\n')
        .rev()
        .take(lines)
        .map(str::len)
        .sum();
    text[text.len() - bytes..].lines()
}
fn old(input: &[u8], count: usize) -> String {
    let text = old_snapshot(Cursor::new(input), input.len() as u64).unwrap();
    let all = text.lines().collect::<Vec<_>>();
    let start = all.len().saturating_sub(count);
    all[start..].join("\n")
}
fn new(input: &[u8], count: usize) -> String {
    let text = new_snapshot(Cursor::new(input), input.len() as u64, MAX_LOG_READ_BYTES).unwrap();
    tail_lines(&text, count).collect::<Vec<_>>().join("\n")
}
fn measure(f: fn(&[u8], usize) -> String, input: &[u8]) -> (u128, usize, usize) {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    let output = f(black_box(input), 120);
    black_box(&output);
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    let calls = CALLS.load(Ordering::Relaxed);
    drop(output);
    let mut timings = [0u128; 5];
    for elapsed in &mut timings {
        let start = Instant::now();
        for _ in 0..50 {
            black_box(f(black_box(input), 120));
        }
        *elapsed = start.elapsed().as_micros() / 50;
    }
    timings.sort();
    (timings[2], peak, calls)
}
fn source_function<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("fn {name}(");
    let start = source
        .find(&needle)
        .expect("benchmark source function exists");
    let body = start + source[start..].find('{').expect("function body exists");
    let mut depth = 0;
    // These extracted functions have no braces inside strings or comments.
    for (offset, byte) in source.as_bytes()[body..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[body..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated benchmark function");
}

fn assert_current_production_source() {
    let production = include_str!("../crates/magicnet-cli/src/mcp_server/logs.rs");
    let benchmark = include_str!("benchmark-log-tail.rs");
    // Whitespace is ignored because this standalone harness can be rustfmt'ed
    // independently of the production module; tokens and comments must match.
    let compact = |text: &str| text.split_whitespace().collect::<String>();
    assert_eq!(
        compact(source_function(production, "read_log_snapshot")),
        compact(source_function(benchmark, "new_snapshot")),
        "refresh candidate snapshot code from production before benchmarking"
    );
    assert_eq!(
        compact(source_function(production, "tail_lines")),
        compact(source_function(benchmark, "tail_lines")),
        "refresh candidate line selection from production before benchmarking"
    );
}

fn main() {
    assert_current_production_source();
    println!(
        "baseline=a5617d6371fe17494fb4b4a6f655a0c8a0f7461e arch={} os={} batch_calls=50 batches=5",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    // Semantic equivalence for mixed Unicode, CR/LF and invalid UTF-8 samples.
    let alphabet: [&[u8]; 6] = [b"a", b"\n", b"\r", "中".as_bytes(), b"\xff", b""];
    for i in 0usize..6usize.pow(6) {
        let mut n = i;
        let mut sample = Vec::new();
        for _ in 0..6 {
            sample.extend_from_slice(alphabet[n % 6]);
            n /= 6;
        }
        for count in [0, 1, 2, 3, 120] {
            assert_eq!(old(&sample, count), new(&sample, count));
        }
    }
    println!("semantic_equivalence_cases=233280");
    let row =
        b"2026-10-30 12:00:00 INFO ordinary runtime event connection completed successfully\n";
    let typical = row.repeat((MAX_LOG_READ_BYTES as usize) / row.len());
    let dense = vec![b'\n'; MAX_LOG_READ_BYTES as usize];
    for (name, input) in [
        ("typical_80_byte_lines", typical),
        ("dense_empty_lines", dense),
    ] {
        assert_eq!(old(&input, 120), new(&input, 120));
        let before = measure(old, &input);
        let after = measure(new, &input);
        println!("{name}: bytes={} lines=120 old_us={} new_us={} old_peak_heap={} new_peak_heap={} old_allocs={} new_allocs={}",input.len(),before.0,after.0,before.1,after.1,before.2,after.2);
    }
}
