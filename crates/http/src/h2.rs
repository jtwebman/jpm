//! HTTP/2 connections for GET requests, and a pool of a few per host.
//!
//! Each connection has one reader thread. It reads every frame, decodes every header block
//! (HPACK's table depends on all of them), and hands each stream its head and its DATA through
//! a channel of its own. Requests and the frames the reader answers with share one writer,
//! behind a lock.
//!
//! Flow control keeps memory bounded: the server may send a stream `STREAM_WINDOW` bytes and
//! the connection `CONN_WINDOW` bytes beyond what the readers of the bodies have taken, so no
//! more than `CONN_WINDOW` waits in memory, however slow the readers are.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::Error;
use crate::frame::{self, Frame, Violation, violation};
use crate::hpack;

/// What the server may send one stream ahead of its reader: a tarball arrives at up to this
/// much per round trip.
pub const STREAM_WINDOW: u32 = 2 << 20;
/// What the server may send the whole connection ahead of the readers: the most memory the
/// connection's bodies can hold.
pub const CONN_WINDOW: u32 = 8 << 20;
/// The largest response head, as SETTINGS_MAX_HEADER_LIST_SIZE counts it.
pub const MAX_HEADER_LIST: usize = 64 * 1024;
/// Streams open at once on one connection, however many the server allows.
pub const MAX_STREAMS: usize = 256;
/// Streams taken to be allowed until the server's SETTINGS say (section 6.5.2 advises servers
/// to allow at least 100).
const FIRST_STREAMS: usize = 100;
/// The last client stream id (section 5.1.1).
const LAST_ID: u32 = (1 << 31) - 1;
/// A connection's window before WINDOW_UPDATE (section 6.9.2).
const DEFAULT_WINDOW: u32 = 65_535;

/// A GET: the host and port as the url has them, and the path with its query. The headers go
/// as given, names lowercased; `authorization` is sent never-indexed.
pub struct Request<'a> {
    pub authority: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
}

pub struct Response {
    pub status: u16,
    /// Names lowercase, in the order sent; pseudo-headers left out.
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// What the reader hands a stream.
enum Event {
    Head(u16, Vec<(String, String)>),
    Data(Vec<u8>),
    End,
    Fail(Error),
}

/// The events for one stream, from the reader to the stream's body.
#[derive(Default)]
struct Chan {
    events: Mutex<VecDeque<Event>>,
    ready: Condvar,
}

impl Chan {
    fn send(&self, e: Event) {
        lock(&self.events).push_back(e);
        self.ready.notify_one();
    }

    /// The next event, or `None` after `stall` without one.
    fn recv(&self, stall: Duration) -> Option<Event> {
        let until = Instant::now() + stall;
        let mut events = lock(&self.events);
        loop {
            if let Some(e) = events.pop_front() {
                return Some(e);
            }
            let left = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
            events = self.ready.wait_timeout(events, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }
}

/// The open streams by id: a few hundred at most, so a list.
#[derive(Default)]
struct Streams(Vec<(u32, Slot)>);

impl Streams {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get_mut(&mut self, id: u32) -> Option<&mut Slot> {
        self.0.iter_mut().find(|s| s.0 == id).map(|s| &mut s.1)
    }

    fn remove(&mut self, id: u32) -> Option<Slot> {
        let i = self.0.iter().position(|s| s.0 == id)?;
        Some(self.0.swap_remove(i).1)
    }
}

/// One HTTP/2 connection. Clones share it.
#[derive(Clone)]
pub struct Conn(Arc<Shared>);

struct Shared {
    state: Mutex<State>,
    out: Mutex<Out>,
    /// The pool this connection is in, told when a stream ends or the connection closes.
    hub: OnceLock<Arc<Hub>>,
    /// How long a stream may wait for a frame.
    stall: Duration,
}

struct Out {
    w: Box<dyn Write + Send>,
    buf: Vec<u8>,
}

struct State {
    streams: Streams,
    /// The next stream's id: every odd id below it has been used.
    next: u32,
    /// Streams promised to requests that have not opened them yet.
    reserved: usize,
    /// Streams the server allows at once, and the most this client opens (at most
    /// `MAX_STREAMS`, or fewer when its pool says).
    allowed: usize,
    cap: usize,
    /// The server's SETTINGS_MAX_FRAME_SIZE, for the header blocks sent.
    max_frame: usize,
    /// The server's SETTINGS_INITIAL_WINDOW_SIZE, and the connection's window for sending.
    /// Nothing is sent but headers; they are kept to check WINDOW_UPDATE against overflow.
    send_initial: i64,
    send: i64,
    /// What the server may still send on the connection, and what the readers have taken
    /// since the last WINDOW_UPDATE.
    recv: i64,
    owed: u32,
    /// Why no stream may start: GOAWAY, a failure, or the connection's end.
    closed: Option<Error>,
    /// The last stream GOAWAY said the server will answer.
    goaway: u32,
}

struct Slot {
    chan: Arc<Chan>,
    /// What the server may still send this stream, and what its reader has taken since the
    /// last WINDOW_UPDATE.
    recv: i64,
    owed: u32,
    send: i64,
    /// The final head has come: a HEADERS after it is trailers.
    head: bool,
    /// The content-length, and the DATA bytes so far.
    length: Option<u64>,
    got: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why the reader stopped: a violation to tell the server about in GOAWAY, or anything else.
enum Stop {
    Violation(Violation),
    Other(Error),
}

impl From<Violation> for Stop {
    fn from(v: Violation) -> Self {
        Stop::Violation(v)
    }
}

impl From<hpack::Error> for Stop {
    fn from(e: hpack::Error) -> Self {
        Stop::Violation(violation(frame::COMPRESSION_ERROR, e.0))
    }
}

/// A new TLS connection, as ALPN made it: HTTP/2, or HTTP/1.1 for the caller's own client.
pub enum Link<T> {
    H2(Conn),
    H1(T),
}

/// HTTP/2 over `tls` when the server picked it by ALPN, else `tls` back as it is.
pub fn tls_link(mut tls: jpm_tls::Stream<TcpStream>, stall: Duration) -> io::Result<Link<jpm_tls::Stream<TcpStream>>> {
    if tls.alpn() != Some(b"h2") {
        return Ok(Link::H1(tls));
    }
    let w = tls.split(tls.get_ref().try_clone()?);
    Ok(Link::H2(Conn::start(tls, w, stall)?))
}

impl Conn {
    /// Start HTTP/2 on a connection: `r` and `w` read and write it, and `w` may be used from
    /// any thread. Sends the preface, SETTINGS and the connection's window, and starts the
    /// reader thread.
    pub fn start(r: impl Read + Send + 'static, w: impl Write + Send + 'static, stall: Duration) -> io::Result<Conn> {
        let state = State {
            streams: Streams::default(),
            next: 1,
            reserved: 0,
            allowed: FIRST_STREAMS,
            cap: MAX_STREAMS,
            max_frame: frame::DEFAULT_MAX_FRAME,
            send_initial: i64::from(DEFAULT_WINDOW),
            send: i64::from(DEFAULT_WINDOW),
            recv: i64::from(CONN_WINDOW),
            owed: 0,
            closed: None,
            goaway: LAST_ID,
        };
        let out = Out { w: Box::new(w), buf: Vec::with_capacity(1024) };
        let shared = Arc::new(Shared { state: Mutex::new(state), out: Mutex::new(out), hub: OnceLock::new(), stall });
        {
            let mut out = lock(&shared.out);
            out.buf.extend_from_slice(frame::PREFACE);
            let mut settings = Vec::new();
            for (id, v) in [
                (frame::ENABLE_PUSH, 0),
                (frame::INITIAL_WINDOW_SIZE, STREAM_WINDOW),
                (frame::MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST as u32),
            ] {
                settings.extend_from_slice(&id.to_be_bytes());
                settings.extend_from_slice(&v.to_be_bytes());
            }
            frame::put(&mut out.buf, frame::SETTINGS, 0, 0, &settings);
            frame::put(&mut out.buf, frame::WINDOW_UPDATE, 0, 0, &(CONN_WINDOW - DEFAULT_WINDOW).to_be_bytes());
            out.flush()?;
        }
        let reader = shared.clone();
        std::thread::Builder::new()
            .name("jpm-h2".into())
            .stack_size(256 * 1024)
            .spawn(move || reader.read_all(Box::new(r)))?;
        Ok(Conn(shared))
    }

    /// Whether no stream may start on it any more.
    pub fn is_closed(&self) -> bool {
        lock(&self.0.state).closed.is_some()
    }

    /// Streams open, and promised.
    pub fn active(&self) -> usize {
        let st = lock(&self.0.state);
        st.streams.len() + st.reserved
    }

    /// Promise a stream to a request, when one is free.
    fn reserve(&self) -> bool {
        let mut st = lock(&self.0.state);
        let free = st.closed.is_none() && st.streams.len() + st.reserved < st.room();
        st.reserved += usize::from(free);
        free
    }

    /// Send a GET, and wait for its response's head.
    pub fn get(&self, req: &Request) -> Result<Response, Error> {
        self.send(req, false)
    }

    /// `get`, on a stream `reserve` promised.
    fn send(&self, req: &Request, reserved: bool) -> Result<Response, Error> {
        let block = request_block(req);
        let chan = Arc::new(Chan::default());
        let shared = &self.0;
        let mut out = lock(&shared.out);
        let (id, max_frame) = {
            let mut st = lock(&shared.state);
            st.reserved -= usize::from(reserved);
            if let Err(e) = &block {
                return Err(e.clone());
            }
            if let Some(e) = &st.closed {
                return Err(Error::unprocessed(e.message.clone()));
            }
            if st.streams.len() >= st.room() {
                return Err(Error::unprocessed("http2: no stream free on the connection"));
            }
            let id = st.next;
            if id == LAST_ID {
                // The last id is left unused: then `next` never passes it.
                st.closed = Some(Error::unprocessed("http2: the connection used up its stream ids"));
            } else {
                st.next += 2;
            }
            let send = st.send_initial;
            let recv = i64::from(STREAM_WINDOW);
            let slot = Slot { chan: chan.clone(), recv, owed: 0, send, head: false, length: None, got: 0 };
            st.streams.0.push((id, slot));
            (id, st.max_frame)
        };
        // HEADERS, then CONTINUATION for what does not fit.
        let block = block.unwrap_or_default();
        let mut chunks = block.chunks(max_frame).peekable();
        let (mut typ, mut flags) = (frame::HEADERS, frame::END_STREAM);
        while let Some(chunk) = chunks.next() {
            let done = if chunks.peek().is_none() { frame::END_HEADERS } else { 0 };
            frame::put(&mut out.buf, typ, flags | done, id, chunk);
            (typ, flags) = (frame::CONTINUATION, 0);
        }
        let sent = out.flush();
        drop(out);
        if let Err(e) = sent {
            shared.fail(Stop::Other(e.into()));
        }

        let mut body = Body { shared: shared.clone(), id, chan, chunk: Vec::new(), at: 0, done: false };
        match body.next()? {
            Event::Head(status, headers) => Ok(Response { status, headers, body }),
            _ => Err(Error::new(io::ErrorKind::InvalidData, "http2: a response without a head")),
        }
    }
}

/// A GET's header block. A name or value with a line break or NUL is refused: in HTTP/1.1 it
/// would add a line of its own, and HTTP/2 must not pass it on either (section 8.2.1).
fn request_block(req: &Request) -> Result<Vec<u8>, Error> {
    let mut block = Vec::with_capacity(256);
    hpack::encode(&mut block, ":method", "GET", false);
    hpack::encode(&mut block, ":scheme", "https", false);
    hpack::encode(&mut block, ":authority", req.authority, false);
    hpack::encode(&mut block, ":path", req.path, false);
    for &(name, value) in req.headers {
        if [name, value].iter().any(|s| s.contains(['\r', '\n', '\0'])) || name.is_empty() {
            return Err(Error::new(io::ErrorKind::InvalidInput, format!("the {name} header has a line break")));
        }
        let name = name.to_ascii_lowercase();
        // Connection-specific fields have no place in HTTP/2 (section 8.2.2).
        if !["host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"].contains(&&*name) {
            hpack::encode(&mut block, &name, value, name == "authorization");
        }
    }
    Ok(block)
}

impl Out {
    fn flush(&mut self) -> io::Result<()> {
        let r = self.w.write_all(&self.buf).and_then(|_| self.w.flush());
        self.buf.clear();
        r
    }
}

impl Shared {
    /// Send frames the reader or a body owes the server. A failure to send fails the connection.
    fn send(&self, f: impl FnOnce(&mut Vec<u8>)) {
        let sent = {
            let mut out = lock(&self.out);
            f(&mut out.buf);
            out.flush()
        };
        if let Err(e) = sent {
            self.fail(Stop::Other(e.into()));
        }
    }

    /// Give back window the readers have taken: `(stream, increment)` pairs, stream 0 for the
    /// connection.
    fn give_back(&self, updates: [(u32, u32); 2]) {
        if updates.iter().any(|u| u.1 > 0) {
            self.send(|buf| {
                for (id, n) in updates.into_iter().filter(|u| u.1 > 0) {
                    frame::put(buf, frame::WINDOW_UPDATE, 0, id, &n.to_be_bytes());
                }
            });
        }
    }

    /// Tell the pool something changed: a stream ended, or the connection closed.
    fn changed(&self) {
        if let Some(hub) = self.hub.get() {
            let _hosts = lock(&hub.hosts);
            hub.changed.notify_all();
        }
    }

    /// The connection is done: every open stream fails, and no new one starts. A protocol
    /// violation is told to the server by GOAWAY.
    fn fail(&self, why: Stop) {
        let err = match &why {
            Stop::Violation(v) => Error::new(io::ErrorKind::InvalidData, v.why),
            Stop::Other(e) => e.clone(),
        };
        let (streams, goaway) = {
            let mut st = lock(&self.state);
            st.closed.get_or_insert_with(|| err.clone());
            (std::mem::take(&mut st.streams.0), st.goaway)
        };
        for (id, slot) in streams {
            slot.chan.send(Event::Fail(Error { unprocessed: id > goaway, ..err.clone() }));
        }
        let mut out = lock(&self.out);
        if let Stop::Violation(v) = why {
            let mut payload = [0; 8];
            payload[4..].copy_from_slice(&v.code.to_be_bytes());
            frame::put(&mut out.buf, frame::GOAWAY, 0, 0, &payload);
            let _ = out.flush();
        }
        // Closes this handle to the socket; the reader's closes when it returns.
        out.w = Box::new(io::sink());
        drop(out);
        self.changed();
    }

    /// The reader thread: every frame until the connection ends.
    fn read_all(self: Arc<Self>, mut r: Box<dyn Read + Send>) {
        let mut decoder = hpack::Decoder::default();
        let mut block = frame::Block::default();
        let mut buf = Vec::new();
        let why = loop {
            let head = match frame::read(&mut *r, frame::DEFAULT_MAX_FRAME, &mut buf) {
                Ok(Some(Ok(h))) => h,
                Ok(Some(Err(v))) => break Stop::Violation(v),
                Ok(None) => break Stop::Other(Error::new(io::ErrorKind::UnexpectedEof, "http2: connection closed")),
                Err(e) => break Stop::Other(e.into()),
            };
            if let Err(why) = self.frame(head, &mut buf, &mut decoder, &mut block) {
                break why;
            }
        };
        let violated = matches!(why, Stop::Violation(_));
        self.fail(why);
        if violated {
            // What the server sent before it read our GOAWAY is read and dropped, some of it:
            // a socket closed with data unread is reset, and the reset can overtake GOAWAY.
            let _ = io::copy(&mut r.take(1 << 20), &mut io::sink());
        }
    }

    fn frame(
        &self,
        head: frame::Head,
        buf: &mut Vec<u8>,
        decoder: &mut hpack::Decoder,
        block: &mut frame::Block,
    ) -> Result<(), Stop> {
        let f = frame::parse(&head, buf)?;
        if block.is_open() || matches!(f, Frame::Headers { .. } | Frame::Continuation { .. }) {
            if let Some((id, end, bytes)) = block.push(&f)? {
                let fields = decoder.decode(bytes, MAX_HEADER_LIST)?;
                self.headers(id, end, fields)?;
            }
            return Ok(());
        }
        match f {
            Frame::Data { stream, end, data, pad } => {
                // The payload becomes the stream's chunk as it is, without a copy.
                let start = usize::from(head.flags & frame::PADDED != 0);
                let len = data.len();
                let mut chunk = std::mem::take(buf);
                chunk.truncate(start + len);
                chunk.drain(..start);
                self.data(stream, end, chunk, pad)
            }
            Frame::Reset { stream, code } => {
                let slot = {
                    let mut st = lock(&self.state);
                    st.opened(stream)?;
                    st.streams.remove(stream)
                };
                if let Some(slot) = slot {
                    let why = format!("http2: the server reset the stream (error code {code})");
                    let e = if code == frame::REFUSED_STREAM {
                        Error::unprocessed(why)
                    } else {
                        Error::new(io::ErrorKind::ConnectionReset, why)
                    };
                    slot.chan.send(Event::Fail(e));
                    self.changed();
                }
                Ok(())
            }
            Frame::Settings { ack: true, .. } => Ok(()),
            Frame::Settings { ack: false, params } => {
                {
                    let mut st = lock(&self.state);
                    for (id, v) in frame::settings(params) {
                        st.setting(id, v)?;
                    }
                }
                self.send(|b| frame::put(b, frame::SETTINGS, frame::ACK, 0, &[]));
                self.changed();
                Ok(())
            }
            Frame::Ping { ack: false, data } => {
                self.send(|b| frame::put(b, frame::PING, frame::ACK, 0, &data));
                Ok(())
            }
            Frame::Ping { ack: true, .. } | Frame::Ignored => Ok(()),
            Frame::GoAway { last, code } => {
                let refused: Vec<(u32, Slot)> = {
                    let mut st = lock(&self.state);
                    st.goaway = st.goaway.min(last);
                    let why = format!("http2: the server is closing the connection (GOAWAY, error code {code})");
                    st.closed.get_or_insert_with(|| Error::unprocessed(why));
                    let (refused, kept) = std::mem::take(&mut st.streams.0).into_iter().partition(|s| s.0 > last);
                    st.streams.0 = kept;
                    refused
                };
                for (_, slot) in refused {
                    slot.chan.send(Event::Fail(Error::unprocessed(
                        "http2: the server closed the connection before this request (GOAWAY)",
                    )));
                }
                self.changed();
                Ok(())
            }
            Frame::WindowUpdate { stream, increment } => {
                let mut st = lock(&self.state);
                let increment = i64::from(increment);
                let window = if stream == 0 {
                    Some(&mut st.send)
                } else {
                    st.opened(stream)?;
                    st.streams.get_mut(stream).map(|s| &mut s.send)
                };
                if let Some(w) = window {
                    *w += increment;
                    if *w > frame::MAX_WINDOW {
                        return Err(violation(frame::FLOW_CONTROL_ERROR, "http2: window above 2^31-1").into());
                    }
                }
                Ok(())
            }
            Frame::Headers { .. } | Frame::Continuation { .. } => unreachable!("taken as a header block"),
        }
    }

    /// A whole header block for stream `id`: its response head, an interim 1xx, or trailers.
    fn headers(&self, id: u32, end: bool, fields: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Stop> {
        let mut st = lock(&self.state);
        st.opened(id)?;
        // A stream reset or given up on: its head was decoded for the table's sake, and is dropped.
        let Some(slot) = st.streams.get_mut(id) else { return Ok(()) };
        if !slot.head {
            let (status, headers) = response_head(fields)?;
            if (100..200).contains(&status) {
                if end {
                    return Err(violation(frame::PROTOCOL_ERROR, "http2: an interim response ends the stream").into());
                }
                return Ok(());
            }
            slot.head = true;
            slot.length = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok());
            slot.chan.send(Event::Head(status, headers));
        } else if !end {
            return Err(violation(frame::PROTOCOL_ERROR, "http2: trailers that do not end the stream").into());
        }
        if end {
            st.finish(id);
            drop(st);
            self.changed();
        }
        Ok(())
    }

    /// DATA for stream `id`: `pad` bytes of padding came with it, taken as read at once.
    fn data(&self, id: u32, end: bool, chunk: Vec<u8>, pad: usize) -> Result<(), Stop> {
        let n = chunk.len() + pad;
        let updates = {
            let mut st = lock(&self.state);
            st.recv -= n as i64;
            if st.recv < 0 {
                return Err(violation(frame::FLOW_CONTROL_ERROR, "http2: DATA beyond the connection's window").into());
            }
            st.opened(id)?;
            if let Some(slot) = st.streams.get_mut(id) {
                if !slot.head {
                    return Err(violation(frame::PROTOCOL_ERROR, "http2: DATA before the response head").into());
                }
                slot.recv -= n as i64;
                if slot.recv < 0 {
                    return Err(violation(frame::FLOW_CONTROL_ERROR, "http2: DATA beyond the stream's window").into());
                }
                slot.got += chunk.len() as u64;
                if !chunk.is_empty() {
                    slot.chan.send(Event::Data(chunk));
                }
                // The data is given back as the stream's reader takes it, and the padding now.
                let updates = st.taken(id, pad);
                if end {
                    st.finish(id);
                }
                updates
            } else {
                // A stream reset or given up on: nothing will read its data.
                st.taken(id, n)
            }
        };
        self.give_back(updates);
        if end {
            self.changed();
        }
        Ok(())
    }
}

impl State {
    /// Streams that may be open at once.
    fn room(&self) -> usize {
        self.allowed.min(self.cap)
    }

    /// Frames may name only streams this client opened (section 5.1): an even id or one not
    /// used yet is a violation. A stream that has since closed is fine, and ignored.
    fn opened(&self, id: u32) -> Result<(), Violation> {
        if id.is_multiple_of(2) || id >= self.next {
            return Err(violation(frame::PROTOCOL_ERROR, "http2: a frame for a stream never opened"));
        }
        Ok(())
    }

    fn setting(&mut self, id: u16, v: u32) -> Result<(), Violation> {
        match id {
            frame::ENABLE_PUSH if v != 0 => {
                return Err(violation(frame::PROTOCOL_ERROR, "http2: the server enabled push"));
            }
            frame::MAX_CONCURRENT_STREAMS => self.allowed = v as usize,
            frame::INITIAL_WINDOW_SIZE => {
                let v = i64::from(v);
                if v > frame::MAX_WINDOW {
                    return Err(violation(frame::FLOW_CONTROL_ERROR, "http2: initial window above 2^31-1"));
                }
                let delta = v - self.send_initial;
                self.send_initial = v;
                for (_, s) in &mut self.streams.0 {
                    s.send += delta;
                    if s.send > frame::MAX_WINDOW {
                        return Err(violation(frame::FLOW_CONTROL_ERROR, "http2: window above 2^31-1"));
                    }
                }
            }
            frame::MAX_FRAME_SIZE => {
                if !(frame::DEFAULT_MAX_FRAME as u32..1 << 24).contains(&v) {
                    return Err(violation(frame::PROTOCOL_ERROR, "http2: bad SETTINGS_MAX_FRAME_SIZE"));
                }
                self.max_frame = v as usize;
            }
            _ => {}
        }
        Ok(())
    }

    /// `n` bytes of stream `id` taken by its reader (or dropped): the WINDOW_UPDATEs to send
    /// now. Each window is given back once a quarter of it is owed.
    fn taken(&mut self, id: u32, n: usize) -> [(u32, u32); 2] {
        let n = n as u32;
        let mut stream = 0;
        if let Some(slot) = self.streams.get_mut(id) {
            slot.owed += n;
            if slot.owed >= STREAM_WINDOW / 4 {
                stream = std::mem::take(&mut slot.owed);
                slot.recv += i64::from(stream);
            }
        }
        self.owed += n;
        let mut conn = 0;
        if self.owed >= CONN_WINDOW / 4 {
            conn = std::mem::take(&mut self.owed);
            self.recv += i64::from(conn);
        }
        [(id, stream), (0, conn)]
    }

    /// The server ended stream `id`: its reader gets the end, or an error when the body's
    /// length is not the one its head gave.
    fn finish(&mut self, id: u32) {
        if let Some(slot) = self.streams.remove(id) {
            let event = match slot.length {
                Some(n) if n != slot.got => Event::Fail(Error::new(
                    io::ErrorKind::InvalidData,
                    format!("http2: a body of {} bytes where content-length said {n}", slot.got),
                )),
                _ => Event::End,
            };
            slot.chan.send(event);
        }
    }
}

/// The status and the other fields of a response head. `:status` must come first and alone
/// among pseudo-headers, and names must be lowercase (section 8.3).
fn response_head(fields: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(u16, Vec<(String, String)>), Violation> {
    let bad = |why| violation(frame::PROTOCOL_ERROR, why);
    let mut fields = fields.into_iter();
    let status = match fields.next() {
        Some((n, v)) if n == b":status" && v.len() == 3 => std::str::from_utf8(&v).ok().and_then(|s| s.parse().ok()),
        _ => None,
    };
    let status = status.filter(|s| (100..600).contains(s)).ok_or(bad("http2: a response head without a status"))?;
    let mut headers = Vec::with_capacity(fields.len());
    for (n, v) in fields {
        if n.first() == Some(&b':') {
            return Err(bad("http2: a bad pseudo-header in a response"));
        }
        if n.is_empty() || n.iter().any(|b| b.is_ascii_uppercase()) {
            return Err(bad("http2: a header name that is not lowercase"));
        }
        headers.push((String::from_utf8_lossy(&n).into_owned(), String::from_utf8_lossy(&v).into_owned()));
    }
    Ok((status, headers))
}

/// A response body, read as its DATA arrives.
pub struct Body {
    shared: Arc<Shared>,
    id: u32,
    chan: Arc<Chan>,
    chunk: Vec<u8>,
    at: usize,
    /// The end has been read.
    done: bool,
}

impl Body {
    /// The next event, the stall timeout an error.
    fn next(&mut self) -> Result<Event, Error> {
        match self.chan.recv(self.shared.stall) {
            Some(Event::Fail(e)) => {
                self.done = true;
                Err(e)
            }
            Some(Event::End) => {
                self.done = true;
                Ok(Event::End)
            }
            Some(e) => Ok(e),
            None => Err(Error::new(
                io::ErrorKind::TimedOut,
                format!("http2: nothing heard for {}s", self.shared.stall.as_secs()),
            )),
        }
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.chunk.len() {
                let n = buf.len().min(self.chunk.len() - self.at);
                buf[..n].copy_from_slice(&self.chunk[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            match self.next()? {
                Event::Data(chunk) => {
                    let updates = lock(&self.shared.state).taken(self.id, chunk.len());
                    self.shared.give_back(updates);
                    (self.chunk, self.at) = (chunk, 0);
                }
                Event::End => return Ok(0),
                Event::Head(..) | Event::Fail(_) => unreachable!("one head, and failures are errors"),
            }
        }
    }
}

impl Drop for Body {
    /// A body not read to its end: the stream is reset, and what the server sent for it is
    /// given back to the connection.
    fn drop(&mut self) {
        let open = lock(&self.shared.state).streams.remove(self.id).is_some();
        if open {
            let id = self.id;
            self.shared.send(|b| frame::put(b, frame::RST_STREAM, 0, id, &frame::CANCEL.to_be_bytes()));
        }
        let left: usize =
            lock(&self.chan.events).drain(..).map(|e| if let Event::Data(d) = e { d.len() } else { 0 }).sum();
        if left > 0 {
            let updates = lock(&self.shared.state).taken(self.id, left);
            self.shared.give_back(updates);
        }
        if open {
            self.shared.changed();
        }
    }
}

// --- the pool ---------------------------------------------------------------------------------

/// A few HTTP/2 connections per host, each carrying many streams. A host whose server picks
/// HTTP/1.1 is remembered, and left to the caller from then on.
pub struct Pool {
    hub: Arc<Hub>,
    per_host: usize,
    /// Streams each connection may carry at once, at most.
    streams: usize,
    stall: Duration,
}

struct Hub {
    /// Each host's connections, by the key the caller gave.
    hosts: Mutex<Vec<(String, Host)>>,
    changed: Condvar,
}

#[derive(Default)]
struct Host {
    conns: Vec<Conn>,
    /// Connections being made.
    connecting: usize,
    /// The server picked HTTP/1.1.
    h1: bool,
}

/// What a request got: an HTTP/2 response, or HTTP/1.1 to use, with the connection just made
/// when there is one.
pub enum Got<T> {
    H2(Response),
    H1(Option<T>),
}

/// How often a request the server never acted on goes again at once, before its error is the
/// caller's to judge.
const REDO: usize = 3;

impl Pool {
    /// Up to `per_host` connections to each host, each carrying up to `streams` streams at once
    /// (and no more than the server allows, nor `MAX_STREAMS`). A stream that hears nothing for
    /// `stall` fails.
    pub fn new(per_host: usize, streams: usize, stall: Duration) -> Self {
        let hub = Arc::new(Hub { hosts: Mutex::default(), changed: Condvar::new() });
        Self { hub, per_host: per_host.max(1), streams: streams.clamp(1, MAX_STREAMS), stall }
    }

    /// A GET to the host `key` names, on a connection `connect` makes when one is needed. A
    /// request GOAWAY or REFUSED_STREAM turned away goes again on another connection.
    pub fn get<T>(
        &self,
        key: &str,
        mut connect: impl FnMut() -> io::Result<Link<T>>,
        req: &Request,
    ) -> Result<Got<T>, Error> {
        let mut redo = 0;
        loop {
            let conn = match self.pick(key, &mut connect)? {
                Ok(conn) => conn,
                Err(h1) => return Ok(Got::H1(h1)),
            };
            match conn.send(req, true) {
                Err(e) if e.unprocessed && redo < REDO => redo += 1,
                r => return r.map(Got::H2),
            }
        }
    }

    /// Whether the host `key` names is known to speak HTTP/1.1 only.
    pub fn is_h1(&self, key: &str) -> bool {
        lock(&self.hub.hosts).iter().any(|h| h.0 == key && h.1.h1)
    }

    /// A connection with a stream promised: the least busy one, or a new one while the host
    /// has fewer than `per_host` and every one has a stream open. `Err` is HTTP/1.1.
    fn pick<T>(
        &self,
        key: &str,
        connect: &mut impl FnMut() -> io::Result<Link<T>>,
    ) -> Result<Result<Conn, Option<T>>, Error> {
        let mut hosts = lock(&self.hub.hosts);
        let until = Instant::now() + self.stall;
        loop {
            let i = match hosts.iter().position(|h| h.0 == key) {
                Some(i) => i,
                None => {
                    hosts.push((key.to_string(), Host::default()));
                    hosts.len() - 1
                }
            };
            let host = &mut hosts[i].1;
            if host.h1 {
                return Ok(Err(None));
            }
            host.conns.retain(|c| !c.is_closed());
            let may_open = host.conns.len() + host.connecting < self.per_host;
            let best = host.conns.iter().map(|c| (c.active(), c)).min_by_key(|(n, _)| *n);
            if let Some((n, c)) = best
                && (n == 0 || !may_open)
                && c.reserve()
            {
                return Ok(Ok(c.clone()));
            }
            if may_open {
                host.connecting += 1;
                drop(hosts);
                let link = connect();
                hosts = lock(&self.hub.hosts);
                self.hub.changed.notify_all();
                let host = &mut hosts[i].1;
                host.connecting -= 1;
                return match link? {
                    Link::H1(t) => {
                        host.h1 = true;
                        Ok(Err(Some(t)))
                    }
                    Link::H2(c) => {
                        let _ = c.0.hub.set(self.hub.clone());
                        lock(&c.0.state).cap = self.streams;
                        let got = c.reserve();
                        host.conns.push(c.clone());
                        if !got {
                            continue;
                        }
                        Ok(Ok(c))
                    }
                };
            }
            let now = Instant::now();
            if now >= until {
                return Err(Error::new(io::ErrorKind::TimedOut, "http2: no connection free"));
            }
            hosts = self.hub.changed.wait_timeout(hosts, until - now).unwrap_or_else(PoisonError::into_inner).0;
        }
    }
}
