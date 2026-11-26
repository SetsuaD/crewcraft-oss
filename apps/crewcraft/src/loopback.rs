//! The app's side of an external sign-in's browser hand-off (RFC 8252, SECURITY-DESIGN.md section 9; task T611d).
//!
//! Owns: listening on the loopback address for exactly one redirect, checking it, answering the browser with a short
//! page, and opening the system browser at the provider's sign-in page. Called by: `external_flow`. Calls: the standard library only.
//!
//! The listener binds `127.0.0.1` on a port the system picks, so nothing outside this computer can reach it, and
//! takes one request: `GET <path>?code=...&state=...`. The `state` must equal the one the app made for this sign-in
//! (compared in constant time), or the request is refused and the wait goes on until the deadline, so a stray or
//! forged request cannot end the sign-in or slip in a code. A provider's `error` ends it with that error. The code is
//! handed back to the caller and never logged.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// The path the provider redirects to.
pub const CALLBACK_PATH: &str = "/callback";
/// The most bytes read from one redirect request.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopbackError {
    /// The loopback port could not be opened.
    Bind(io::ErrorKind),
    /// No acceptable redirect arrived before the deadline.
    TimedOut,
    /// The provider sent the browser back with an error (`access_denied`, for example).
    Provider(String),
    /// The person cancelled the sign-in, or the app is closing (task T611h).
    Cancelled,
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoopbackError::Bind(kind) => write!(f, "could not listen for the sign-in redirect: {kind}"),
            LoopbackError::TimedOut => f.write_str("the sign-in was not finished in time"),
            LoopbackError::Provider(error) => write!(f, "the sign-in provider refused: {error}"),
            LoopbackError::Cancelled => f.write_str("the sign-in was cancelled"),
        }
    }
}

impl std::error::Error for LoopbackError {}

/// A code the provider returned. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(pub String);

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(..)")
    }
}

/// A listener waiting for one redirect.
#[derive(Debug)]
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    /// Listen on `127.0.0.1` on a free port.
    pub fn bind() -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).map_err(|e| LoopbackError::Bind(e.kind()))?;
        let port = listener.local_addr().map_err(|e| LoopbackError::Bind(e.kind()))?.port();
        listener.set_nonblocking(true).map_err(|e| LoopbackError::Bind(e.kind()))?;
        Ok(Self { listener, port })
    }

    /// The redirect URI to register in the authorization request: `http://127.0.0.1:<port>/callback`.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    /// Wait until `deadline` for a redirect carrying `expected_state`, and return its code. Requests with another
    /// state, another path or method, or nothing usable are answered and ignored.
    pub fn wait(self, expected_state: &str, deadline: Instant) -> Result<Code, LoopbackError> {
        self.wait_unless(expected_state, deadline, &|| false)
    }

    /// As `wait`, but ending with `Cancelled` as soon as `cancelled` says so (it is asked every 25 ms while no request
    /// is in progress), so a person can stop waiting and a closing app is not held up (task T611h).
    pub fn wait_unless(self, expected_state: &str, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<Code, LoopbackError> {
        loop {
            if cancelled() {
                return Err(LoopbackError::Cancelled);
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(outcome) = handle(stream, expected_state, deadline) {
                        return outcome;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LoopbackError::TimedOut);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(LoopbackError::TimedOut);
                    }
                }
            }
        }
    }
}

/// One connection: `Some` ends the wait (a code, or the provider's error), `None` keeps waiting.
fn handle(mut stream: TcpStream, expected_state: &str, deadline: Instant) -> Option<Result<Code, LoopbackError>> {
    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(10)).min(Duration::from_secs(5));
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(left));
    let _ = stream.set_write_timeout(Some(left));
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
        if request.len() > MAX_REQUEST_BYTES {
            answer(&mut stream, "400 Bad Request", "This request is too large.");
            return None;
        }
    }
    let line = request.split(|&b| b == b'\r').next().and_then(|l| std::str::from_utf8(l).ok()).unwrap_or("");
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if method != "GET" || path != CALLBACK_PATH {
        answer(&mut stream, "404 Not Found", "There is nothing here.");
        return None;
    }
    let params = parse_query(query);
    let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let state_ok = get("state").is_some_and(|state| constant_time_eq(state.as_bytes(), expected_state.as_bytes()));
    if !state_ok {
        answer(&mut stream, "400 Bad Request", "This sign-in link does not belong to the sign-in CrewCraft started.");
        return None;
    }
    if let Some(error) = get("error") {
        answer(&mut stream, "200 OK", "The sign-in was not completed. You can close this tab and return to CrewCraft.");
        return Some(Err(LoopbackError::Provider(error.chars().filter(|c| c.is_ascii_graphic()).take(64).collect())));
    }
    match get("code").filter(|code| !code.is_empty() && code.len() <= 2048 && code.bytes().all(|b| b.is_ascii_graphic())) {
        Some(code) => {
            answer(&mut stream, "200 OK", "You are signed in. You can close this tab and return to CrewCraft.");
            Some(Ok(Code(code.to_owned())))
        }
        None => {
            answer(&mut stream, "400 Bad Request", "The sign-in provider sent no code.");
            None
        }
    }
}

fn answer(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>CrewCraft</title></head>\
         <body style=\"font-family:system-ui,sans-serif;margin:3em\"><p>{text}</p></body></html>"
    );
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Referrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body.as_bytes())).and_then(|()| stream.flush());
}

/// `application/x-www-form-urlencoded` pairs, percent-decoded (`+` is a space). Undecodable pairs are dropped.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((percent_decode(k)?, percent_decode(v)?))
        })
        .collect()
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Open the system browser at `url` (an https sign-in page), on the desktop systems. Phones open it through their own
/// platform calls instead. The URL is passed as one argument, never through a shell.
pub fn open_browser(url: &str) -> io::Result<()> {
    if !url.starts_with("https://") || url.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only an https URL without spaces is opened"));
    }
    let mut command = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ())
}
