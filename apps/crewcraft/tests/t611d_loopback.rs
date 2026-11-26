//! T611d: the app's loopback receiver for an external sign-in (RFC 8252): one redirect on 127.0.0.1, its state checked,
//! the code handed back; stray, forged and malformed requests answered and ignored; a provider's error and the deadline
//! end the wait. Real loopback connections; no browser is opened.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use crewcraft::loopback::{CALLBACK_PATH, Code, Loopback, LoopbackError, open_browser, parse_query};

const STATE: &str = "s7Ate-Q2xKz_0aBcDeFgHiJkLmNoPqRsTuVwXyZ01234";

/// Send one raw request to the receiver and return the status line it answered with.
fn send(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer.lines().next().unwrap_or("").to_owned()
}

fn get(port: u16, target: &str) -> String {
    send(port, &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"))
}

fn start(deadline: Duration) -> (u16, String, thread::JoinHandle<Result<Code, LoopbackError>>) {
    let loopback = Loopback::bind().unwrap();
    let uri = loopback.redirect_uri();
    let port: u16 = uri.trim_start_matches("http://127.0.0.1:").trim_end_matches(CALLBACK_PATH).parse().unwrap();
    let handle = thread::spawn(move || loopback.wait(STATE, Instant::now() + deadline));
    (port, uri, handle)
}

#[test]
fn the_redirect_with_the_right_state_gives_the_code() {
    let (port, uri, handle) = start(Duration::from_secs(10));
    assert_eq!(uri, format!("http://127.0.0.1:{port}/callback"));
    // Stray and forged requests first: each is answered and the wait goes on.
    assert!(get(port, "/").contains("404"));
    assert!(send(port, &format!("POST {CALLBACK_PATH}?code=x&state={STATE} HTTP/1.1\r\nContent-Length: 0\r\n\r\n")).contains("404"));
    assert!(get(port, &format!("{CALLBACK_PATH}?code=forged&state=not-the-state")).contains("400"));
    assert!(get(port, &format!("{CALLBACK_PATH}?code=forged")).contains("400"));
    assert!(get(port, &format!("{CALLBACK_PATH}?state={STATE}")).contains("400"), "no code");
    // The real one, with percent-encoding in the code.
    assert!(get(port, &format!("{CALLBACK_PATH}?state={STATE}&code=ab%2Fc%3D&session_state=x")).contains("200"));
    let code = handle.join().unwrap().unwrap();
    assert_eq!(code, Code("ab/c=".to_owned()));
    assert_eq!(format!("{code:?}"), "Code(..)", "Debug never shows the code");
}

#[test]
fn a_provider_error_ends_the_wait_but_only_with_the_right_state() {
    let (port, _, handle) = start(Duration::from_secs(10));
    assert!(get(port, &format!("{CALLBACK_PATH}?error=access_denied&state=wrong")).contains("400"));
    assert!(get(port, &format!("{CALLBACK_PATH}?error=access_denied&state={STATE}")).contains("200"));
    assert_eq!(handle.join().unwrap(), Err(LoopbackError::Provider("access_denied".to_owned())));
}

#[test]
fn nothing_usable_before_the_deadline_times_out() {
    let started = Instant::now();
    let (port, _, handle) = start(Duration::from_millis(600));
    assert!(get(port, &format!("{CALLBACK_PATH}?code=x&state=wrong")).contains("400"));
    assert_eq!(handle.join().unwrap(), Err(LoopbackError::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn queries_are_decoded_and_only_https_pages_are_opened() {
    assert_eq!(
        parse_query("a=1&b=x+y&c=%41%42&&d"),
        vec![("a".into(), "1".into()), ("b".into(), "x y".into()), ("c".into(), "AB".into()), ("d".into(), String::new())]
    );
    assert!(parse_query("bad=%zz").is_empty());
    for url in ["http://id.example.org/", "file:///etc/passwd", "https://id.example.org/a b", "javascript:alert(1)"] {
        assert!(open_browser(url).is_err(), "{url}");
    }
}
