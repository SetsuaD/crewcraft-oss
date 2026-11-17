#![allow(clippy::unwrap_used)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crewcraft_server::listener::Listener;

const WAIT: Duration = Duration::from_secs(5);

fn connect(address: SocketAddr) -> TcpStream {
    let peer = TcpStream::connect_timeout(&address, WAIT).unwrap();
    peer.set_read_timeout(Some(WAIT)).unwrap();
    peer
}

fn assert_bare_close(mut peer: TcpStream) {
    let mut byte = [0];
    match peer.read(&mut byte) {
        Ok(read) => assert_eq!(read, 0),
        Err(error) => assert!(matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)),
    }
}

#[test]
fn refuses_nonloopback_before_binding() {
    for address in ["0.0.0.0:0", "192.0.2.1:0", "[::]:0"] {
        let result = Listener::bind(address.parse().unwrap(), NonZeroUsize::MIN);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }
}

#[test]
fn caps_handlers_reuses_capacity_after_a_panic_and_shuts_down() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), NonZeroUsize::new(2).unwrap()).unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let (started, acceptances) = mpsc::channel();
    let server = thread::spawn(move || {
        listener.serve(&stop, move |mut peer| {
            peer.set_read_timeout(Some(WAIT)).unwrap();
            started.send(peer.peer_addr().unwrap()).unwrap();
            let mut release = [0];
            if peer.read_exact(&mut release).is_ok() {
                assert_ne!(release, [b'!'], "synthetic handler panic");
            }
        })
    });

    let mut first = connect(address);
    assert_eq!(acceptances.recv_timeout(WAIT).unwrap(), first.local_addr().unwrap());
    let second = connect(address);
    assert_eq!(acceptances.recv_timeout(WAIT).unwrap(), second.local_addr().unwrap());
    assert_bare_close(connect(address));
    assert!(matches!(acceptances.try_recv(), Err(mpsc::TryRecvError::Empty)));

    first.write_all(b"!").unwrap();
    assert_bare_close(first);
    let deadline = Instant::now() + WAIT;
    let replacement = loop {
        assert!(Instant::now() < deadline, "handler capacity did not recover");
        let candidate = connect(address);
        if let Ok(accepted) = acceptances.recv_timeout(Duration::from_millis(50)) {
            assert_eq!(accepted, candidate.local_addr().unwrap());
            break candidate;
        }
        drop(candidate);
    };

    shutdown.store(true, Ordering::Release);
    drop(second);
    drop(replacement);
    server.join().unwrap().unwrap();
    assert!(TcpStream::connect_timeout(&address, WAIT).is_err());
}
