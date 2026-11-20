//! Standalone loopback response-limit benchmark; never linked into MagicNet.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(magicnet_candidate))]
#[path = "local_http-before.instrumented.rs"]
mod local_http;
#[cfg(magicnet_candidate)]
#[path = "local_http-after.instrumented.rs"]
mod local_http;

const BODY_BYTES: usize = 8 * 1024 * 1024;
const CALLER_LIMIT: usize = 1024 * 1024;
const LIMIT_ERROR: &str = "local API response exceeds the read limit";

#[derive(Clone, Copy)]
struct Counters {
    live: isize,
    peak: usize,
    requested: usize,
    allocations: usize,
    received: usize,
    reads: usize,
}
const ZERO_COUNTERS: Counters = Counters {
    live: 0, peak: 0, requested: 0, allocations: 0, received: 0, reads: 0,
};
thread_local! {
    // Const, non-dropping TLS avoids allocating from the allocator observer.
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static COUNTERS: Cell<Counters> = const { Cell::new(ZERO_COUNTERS) };
}
struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn account(delta: isize, requested: usize, allocation: bool) {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = COUNTERS.try_with(|cell| {
            let mut value = cell.get();
            value.live += delta;
            if value.live >= 0 {
                value.peak = value.peak.max(value.live as usize);
            }
            value.requested += requested;
            value.allocations += usize::from(allocation);
            cell.set(value);
        });
    }
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() { account(layout.size() as isize, layout.size(), true); }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() { account(layout.size() as isize, layout.size(), true); }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        account(-(layout.size() as isize), 0, false);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            account(size as isize - layout.size() as isize, size, true);
        }
        result
    }
}

// Inserted at the same response-read boundary in BOTH frozen source copies.
// The server thread is never tracked, so its fixture allocations are excluded.
fn record_response_read(bytes: usize) {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        COUNTERS.with(|cell| {
            let mut value = cell.get();
            value.received += bytes;
            value.reads += 1;
            cell.set(value);
        });
    }
}
#[derive(Clone, Copy)]
enum Framing { ContentLength, CloseDelimited }
impl Framing {
    fn label(self) -> &'static str {
        match self {
            Self::ContentLength => "content_length",
            Self::CloseDelimited => "close_delimited",
        }
    }
}
struct ServerStats { accepted_body_bytes: usize, completed: bool }
struct Row { counters: Counters, elapsed_us: u128, server: ServerStats }

fn serve(listener: TcpListener, framing: Framing) -> io::Result<ServerStats> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "fixture accept"));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true)?;
    read_request(&mut stream)?;
    let head = match framing {
        Framing::ContentLength =>
            b"HTTP/1.0 200 OK\r\nContent-Length: 8388608\r\nConnection: close\r\n\r\n".as_slice(),
        Framing::CloseDelimited =>
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
    };
    stream.write_all(head)?;
    // No 8 MiB fixture allocation: reuse a fixed stack block.
    let block = [b'x'; 8192];
    let mut accepted_body_bytes = 0;
    while accepted_body_bytes < BODY_BYTES {
        let count = block.len().min(BODY_BYTES - accepted_body_bytes);
        match stream.write(&block[..count]) {
            Ok(0) => break,
            Ok(written) => accepted_body_bytes += written,
            Err(error) if matches!(error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(ServerStats {
        accepted_body_bytes, completed: accepted_body_bytes == BODY_BYTES,
    })
}
fn read_request(stream: &mut TcpStream) -> io::Result<()> {
    let mut tail = [0; 4];
    for _ in 0..16 * 1024 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        tail.rotate_left(1);
        tail[3] = byte[0];
        if tail == *b"\r\n\r\n" { return Ok(()); }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "fixture request headers too large"))
}
fn request(api: &str) -> Result<Vec<u8>, String> {
    #[cfg(magicnet_candidate)]
    {
        local_http::request_with_timeout(
            api, "GET", "/configs", "", Duration::from_secs(5), CALLER_LIMIT,
        )
    }
    #[cfg(not(magicnet_candidate))]
    {
        // Original webui native fallback: receive, THEN check caller budget.
        let body = local_http::request_with_timeout(
            api, "GET", "/configs", "", Duration::from_secs(5),
        )?;
        if body.len() <= CALLER_LIMIT { Ok(body) } else { Err(LIMIT_ERROR.to_string()) }
    }
}
fn measure(framing: Framing) -> Result<Row, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let api = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
    let server = thread::spawn(move || serve(listener, framing));
    COUNTERS.with(|cell| cell.set(ZERO_COUNTERS));
    TRACKING.with(|cell| cell.set(true));
    let started = Instant::now();
    let result = request(&api);
    let elapsed_us = started.elapsed().as_micros();
    TRACKING.with(|cell| cell.set(false));
    let counters = COUNTERS.with(Cell::get);
    let server = server.join()
        .map_err(|_| "fixture server panicked".to_string())?
        .map_err(|e| format!("fixture server: {e}"))?;
    if result.as_deref().err().map(String::as_str) != Some(LIMIT_ERROR) {
        return Err(format!("unexpected request result: {result:?}"));
    }
    if counters.live < 0 || counters.received == 0 {
        return Err("invalid counter scope or missing response-read hook".to_string());
    }
    Ok(Row { counters, elapsed_us, server })
}
fn main() -> Result<(), String> {
    let iterations = std::env::args().nth(1)
        .map(|s| s.parse::<usize>().map_err(|_| "invalid iteration count"))
        .transpose()?.unwrap_or(7);
    if !(1..=100).contains(&iterations) {
        return Err("iteration count must be in 1..=100".to_string());
    }
    let variant = if cfg!(magicnet_candidate) { "after" } else { "before" };
    for framing in [Framing::ContentLength, Framing::CloseDelimited] {
        measure(framing)?; // Discard one warm-up sample.
        for iteration in 1..=iterations {
            let row = measure(framing)?;
            println!(
                concat!(
                    "{{\"schema\":1,\"variant\":\"{}\",\"case\":\"{}\",",
                    "\"scope\":\"loopback_API_response_limit_not_RSS_or_network_throughput\",",
                    "\"iteration\":{},\"response_body_offered_bytes\":{},",
                    "\"caller_limit_bytes\":{},\"client_socket_read_bytes\":{},",
                    "\"client_read_calls\":{},\"peak_live_heap_bytes\":{},",
                    "\"total_requested_heap_bytes\":{},\"allocation_calls\":{},",
                    "\"live_heap_bytes_at_return\":{},\"elapsed_us\":{},",
                    "\"server_write_accepted_body_bytes\":{},\"server_completed_body\":{},",
                    "\"outcome\":\"caller_limit_rejected\"}}"
                ),
                variant, framing.label(), iteration, BODY_BYTES, CALLER_LIMIT,
                row.counters.received, row.counters.reads, row.counters.peak,
                row.counters.requested, row.counters.allocations, row.counters.live,
                row.elapsed_us, row.server.accepted_body_bytes, row.server.completed,
            );
        }
    }
    Ok(())
}
