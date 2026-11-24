//! A TCP listener with a bounded number of active handlers: loopback-only for the lab (`bind`), any address for a
//! network server (`bind_network`, task T230).

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const IDLE_POLL: Duration = Duration::from_millis(10);

pub struct Listener {
    socket: TcpListener,
    capacity: NonZeroUsize,
}

impl Listener {
    /// Bind an IPv4 or IPv6 loopback address. Port zero lets the operating system choose a port.
    pub fn bind(address: SocketAddr, capacity: NonZeroUsize) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "listener address must be loopback"));
        }
        Self::bind_network(address, capacity)
    }

    /// Bind any local address, including every interface (`0.0.0.0`, or `::`, which on most systems also accepts
    /// IPv4). Port zero lets the operating system choose a port. The listener does not filter peers by address: only
    /// a peer that passes TLS admission ever receives application bytes.
    pub fn bind_network(address: SocketAddr, capacity: NonZeroUsize) -> io::Result<Self> {
        let socket = TcpListener::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, capacity })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Accept until `shutdown` becomes true or accepting a peer fails. At capacity,
    /// drop new sockets without writing to them. Join active handlers before returning: each open connection's read
    /// side is shut first, so a request in progress still gets its answer but a client that keeps its connection
    /// open (a signed-in app polls every few seconds) cannot keep the server from stopping (task T240).
    ///
    /// The handler receives a blocking socket and owns its handshake and application deadlines.
    pub fn serve<F>(self, shutdown: &AtomicBool, handler: F) -> io::Result<()>
    where
        F: Fn(TcpStream) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut workers = Vec::new();
        let outcome = self.accept_until(shutdown, &handler, &mut workers);
        drop(self.socket);
        for worker in &workers {
            if let Ok(held) = worker.peer.lock()
                && let Some(peer) = held.as_ref()
            {
                let _ = peer.shutdown(Shutdown::Read);
            }
        }
        for worker in workers {
            let _ = worker.thread.join();
        }
        outcome
    }

    fn accept_until<F>(&self, shutdown: &AtomicBool, handler: &Arc<F>, workers: &mut Vec<Worker>) -> io::Result<()>
    where
        F: Fn(TcpStream) + Send + Sync + 'static,
    {
        while !shutdown.load(Ordering::Acquire) {
            match self.socket.accept() {
                Ok((peer, _)) => {
                    reap_finished(workers);
                    if workers.len() == self.capacity.get() || shutdown.load(Ordering::Acquire) {
                        continue;
                    }
                    let handler = Arc::clone(handler);
                    let watch = Arc::new(Mutex::new(peer.try_clone().ok()));
                    let release = Release(Arc::clone(&watch));
                    let thread = thread::Builder::new().spawn(move || {
                        // Let go of the second handle when the handler ends (or panics), so its socket closes then.
                        let _release = release;
                        if peer.set_nonblocking(false).is_ok() {
                            handler(peer);
                        }
                    })?;
                    workers.push(Worker { thread, peer: watch });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(IDLE_POLL),
                Err(error) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

/// One connection's handler thread, and a second handle on its socket to end it at shutdown (dropped by the handler
/// thread when it ends, so it never keeps a finished connection open).
struct Worker {
    thread: JoinHandle<()>,
    peer: Arc<Mutex<Option<TcpStream>>>,
}

/// Drops the second socket handle when the handler thread ends.
struct Release(Arc<Mutex<Option<TcpStream>>>);

impl Drop for Release {
    fn drop(&mut self) {
        let mut held = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        held.take();
    }
}

fn reap_finished(workers: &mut Vec<Worker>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].thread.is_finished() {
            let _ = workers.swap_remove(index).thread.join();
        } else {
            index += 1;
        }
    }
}
