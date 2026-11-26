//! A small, strict HTTPS client for the server's outgoing calls (task T611c, SECURITY-DESIGN.md section 9): an
//! OpenID Connect provider's discovery document and keys, the token exchange, and an external authorizer.
//!
//! Owns: URL checks (https only, no credentials in the URL), connecting with timeouts, TLS through rustls with either
//! the public web roots or a pinned CA bundle (an organization's private CA), an optional client certificate (mutual
//! TLS to an authorizer), one request per connection (`Connection: close`), and reading the answer strictly: a status
//! line, at most `MAX_HEADER_BYTES` of headers, and a body by `Content-Length` or chunked encoding, never larger than
//! the caller's limit. Redirects are not followed; they are an error, so a provider cannot send the server elsewhere.
//! Called by: the server's identity and authorizer code (wiring comes in a later task). Calls: `rustls` (ring), and
//! `webpki-roots` for the public roots.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// The most header bytes read from a response.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The default body limit.
pub const DEFAULT_MAX_BODY: usize = 256 * 1024;
/// The default time allowed for connecting, and for each read or write.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Only `https://` URLs are used.
    NotHttps,
    /// The URL is not one this client accepts (no host, credentials in it, a bad port, spaces...).
    BadUrl(&'static str),
    /// No address of the host could be reached.
    Connect(io::ErrorKind),
    /// The TLS handshake or connection failed (an untrusted certificate, a refused client certificate...).
    Tls(String),
    Timeout,
    /// The server answered with a redirect; it is not followed.
    Redirect(u16),
    /// The answer is larger than allowed.
    TooLarge,
    /// The answer is not well-formed HTTP; the text names the part.
    Malformed(&'static str),
    /// The certificates or key given to `Client::new` are not usable.
    Config(String),
    /// `Response::ok` on an answer that is not 2xx.
    Status(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotHttps => f.write_str("only https URLs are used"),
            Error::BadUrl(why) => write!(f, "bad URL: {why}"),
            Error::Connect(kind) => write!(f, "could not connect: {kind}"),
            Error::Tls(why) => write!(f, "TLS failed: {why}"),
            Error::Timeout => f.write_str("timed out"),
            Error::Redirect(status) => write!(f, "redirect ({status}) not followed"),
            Error::TooLarge => f.write_str("the answer is too large"),
            Error::Malformed(what) => write!(f, "malformed answer: {what}"),
            Error::Config(why) => write!(f, "client configuration: {why}"),
            Error::Status(status) => write!(f, "status {status}"),
        }
    }
}

impl std::error::Error for Error {}

/// Which certificate authorities a server's certificate may chain to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Roots {
    /// The public web roots (Mozilla's list, `webpki-roots`).
    Public,
    /// Only the CAs in this PEM bundle (an organization's private CA).
    Pem(Vec<u8>),
}

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl Response {
    /// The body of a 2xx answer; any other status is `Error::Status`.
    pub fn ok(self) -> Result<Vec<u8>, Error> {
        if (200..300).contains(&self.status) { Ok(self.body) } else { Err(Error::Status(self.status)) }
    }
}

/// A client with its TLS settings and limits. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    config: Arc<ClientConfig>,
    timeout: Duration,
    max_body: usize,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").field("timeout", &self.timeout).field("max_body", &self.max_body).finish_non_exhaustive()
    }
}

/// A client certificate chain and its private key, for mutual TLS.
pub type Identity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

impl Client {
    /// A client trusting `roots`, presenting `identity` when a server asks for a certificate.
    pub fn new(roots: &Roots, identity: Option<Identity>) -> Result<Self, Error> {
        let mut store = RootCertStore::empty();
        match roots {
            Roots::Public => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Roots::Pem(pem) => {
                for cert in CertificateDer::pem_slice_iter(pem) {
                    let cert = cert.map_err(|e| Error::Config(format!("CA bundle: {e}")))?;
                    store.add(cert).map_err(|e| Error::Config(format!("CA bundle: {e}")))?;
                }
                if store.is_empty() {
                    return Err(Error::Config("the CA bundle holds no certificate".into()));
                }
            }
        }
        let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Config(e.to_string()))?
            .with_root_certificates(store);
        let config = match identity {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| Error::Config(e.to_string()))?,
            None => builder.with_no_client_auth(),
        };
        Ok(Self { config: Arc::new(config), timeout: DEFAULT_TIMEOUT, max_body: DEFAULT_MAX_BODY })
    }

    /// The same client with another timeout and body limit.
    pub fn with_limits(mut self, timeout: Duration, max_body: usize) -> Self {
        self.timeout = timeout;
        self.max_body = max_body;
        self
    }

    pub fn get(&self, url: &str) -> Result<Response, Error> {
        self.request("GET", url, None)
    }

    /// POST `body` with `content_type` (for example `application/x-www-form-urlencoded` or `application/json`).
    pub fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Response, Error> {
        if content_type.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(Error::BadUrl("content type"));
        }
        self.request("POST", url, Some((content_type, body)))
    }

    fn request(&self, method: &str, url: &str, body: Option<(&str, &[u8])>) -> Result<Response, Error> {
        let target = Target::parse(url)?;
        let tcp = self.connect(&target)?;
        let name = ServerName::try_from(target.host.clone()).map_err(|_| Error::BadUrl("host"))?;
        let connection = ClientConnection::new(Arc::clone(&self.config), name).map_err(|e| Error::Tls(e.to_string()))?;
        let mut stream = StreamOwned::new(connection, tcp);

        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: CrewCraft\r\nAccept: application/json\r\nConnection: close\r\n",
            target.path, target.authority
        );
        if let Some((content_type, bytes)) = body {
            head.push_str(&format!("Content-Type: {content_type}\r\nContent-Length: {}\r\n", bytes.len()));
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        if let Some((_, bytes)) = body {
            request.extend_from_slice(bytes);
        }
        stream.write_all(&request).and_then(|()| stream.flush()).map_err(io_error)?;
        read_response(&mut stream, self.max_body)
    }

    fn connect(&self, target: &Target) -> Result<TcpStream, Error> {
        let addrs = (target.host.as_str(), target.port).to_socket_addrs().map_err(|e| Error::Connect(e.kind()))?;
        let mut last = io::ErrorKind::NotFound;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(tcp) => {
                    tcp.set_read_timeout(Some(self.timeout)).map_err(|e| Error::Connect(e.kind()))?;
                    tcp.set_write_timeout(Some(self.timeout)).map_err(|e| Error::Connect(e.kind()))?;
                    return Ok(tcp);
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => last = io::ErrorKind::TimedOut,
                Err(e) => last = e.kind(),
            }
        }
        Err(if last == io::ErrorKind::TimedOut { Error::Timeout } else { Error::Connect(last) })
    }
}

fn io_error(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Error::Timeout,
        io::ErrorKind::InvalidData => Error::Tls(e.to_string()),
        kind => Error::Connect(kind),
    }
}

/// The parts of an https URL this client uses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    /// `host` or `host:port` as it goes in the Host header.
    authority: String,
    /// The path and query, starting with `/`.
    path: String,
}

impl Target {
    fn parse(url: &str) -> Result<Self, Error> {
        let rest = url.strip_prefix("https://").ok_or(Error::NotHttps)?;
        if url.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(Error::BadUrl("characters"));
        }
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = path.split('#').next().unwrap_or("/");
        let path = if path.starts_with('?') { format!("/{path}") } else { path.to_owned() };
        if authority.is_empty() {
            return Err(Error::BadUrl("no host"));
        }
        if authority.contains('@') {
            return Err(Error::BadUrl("credentials in the URL"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6.find(']').ok_or(Error::BadUrl("host"))?;
            let port = match &v6[end + 1..] {
                "" => 443,
                p => p.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).ok_or(Error::BadUrl("port"))?,
            };
            (v6[..end].to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_owned(), p.parse::<u16>().map_err(|_| Error::BadUrl("port"))?),
                None => (authority.to_owned(), 443),
            }
        };
        if host.is_empty() || port == 0 {
            return Err(Error::BadUrl("host"));
        }
        Ok(Self { host, port, authority: authority.to_owned(), path })
    }
}

/// Read one answer: status line and headers (at most `MAX_HEADER_BYTES`), then the body by `Content-Length` or chunked
/// encoding, at most `max_body` bytes. Without either, the body runs to a clean TLS close.
fn read_response(stream: &mut impl Read, max_body: usize) -> Result<Response, Error> {
    let mut buf = Vec::new();
    let header_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Error::Malformed("headers too long"));
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).map_err(io_error)?;
        if n == 0 {
            return Err(Error::Malformed("closed before the headers ended"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(Error::Malformed("headers too long"));
    }
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| Error::Malformed("headers are not text"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(Error::Malformed("status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Error::Malformed("status line"));
    }
    let status = parts.next().and_then(|s| (s.len() == 3).then(|| s.parse::<u16>().ok()).flatten()).ok_or(Error::Malformed("status"))?;
    let (mut length, mut chunked, mut content_type) = (None::<usize>, false, None);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Error::Malformed("header line"))?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n = value.parse::<usize>().map_err(|_| Error::Malformed("content-length"))?;
                if length.is_some_and(|l| l != n) {
                    return Err(Error::Malformed("conflicting content-length"));
                }
                length = Some(n);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(Error::Malformed("transfer-encoding"));
                }
                chunked = true;
            }
            "content-type" => content_type = Some(value.to_owned()),
            _ => {}
        }
    }
    if (300..400).contains(&status) {
        return Err(Error::Redirect(status));
    }
    if chunked && length.is_some() {
        return Err(Error::Malformed("both content-length and chunked"));
    }
    let mut rest = Rest { pre: buf[header_end + 4..].to_vec(), pos: 0, stream };
    let body = if chunked {
        read_chunked(&mut rest, max_body)?
    } else if let Some(n) = length {
        if n > max_body {
            return Err(Error::TooLarge);
        }
        let mut body = vec![0u8; n];
        rest.read_exact(&mut body)
            .map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof { Error::Malformed("body shorter than content-length") } else { io_error(e) })?;
        body
    } else {
        let mut body = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = rest.read(&mut chunk).map_err(io_error)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > max_body {
                return Err(Error::TooLarge);
            }
        }
        body
    };
    Ok(Response { status, content_type, body })
}

fn read_chunked(rest: &mut impl Read, max_body: usize) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    loop {
        let line = read_line(rest)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| Error::Malformed("chunk size"))?;
        if size == 0 {
            // Trailers, if any, end with an empty line.
            while !read_line(rest)?.is_empty() {}
            return Ok(body);
        }
        if body.len().saturating_add(size) > max_body {
            return Err(Error::TooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        rest.read_exact(&mut body[start..]).map_err(|_| Error::Malformed("chunk shorter than its size"))?;
        if !read_line(rest)?.is_empty() {
            return Err(Error::Malformed("chunk not followed by CRLF"));
        }
    }
}

fn read_line(rest: &mut impl Read) -> Result<String, Error> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = rest.read(&mut byte).map_err(io_error)?;
        if n == 0 {
            return Err(Error::Malformed("closed inside a chunked body"));
        }
        if byte[0] == b'\n' {
            if line.last() != Some(&b'\r') {
                return Err(Error::Malformed("bare LF"));
            }
            line.pop();
            return String::from_utf8(line).map_err(|_| Error::Malformed("chunk line"));
        }
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(Error::Malformed("chunk line too long"));
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The bytes already read past the headers, then the stream.
struct Rest<'a, R: Read> {
    pre: Vec<u8>,
    pos: usize,
    stream: &'a mut R,
}

impl<R: Read> Read for Rest<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.pre.len() {
            let n = out.len().min(self.pre.len() - self.pos);
            out[..n].copy_from_slice(&self.pre[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.stream.read(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Target};

    #[test]
    fn urls_are_checked() {
        let t = Target::parse("https://id.example.org/application/o/chat/.well-known/openid-configuration").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((t.host.as_str(), t.port, t.authority.as_str()), ("id.example.org", 443, "id.example.org"));
        assert_eq!(t.path, "/application/o/chat/.well-known/openid-configuration");
        let t = Target::parse("https://127.0.0.1:8443?x=1#frag").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((t.host.as_str(), t.port, t.path.as_str()), ("127.0.0.1", 8443, "/?x=1"));
        let t = Target::parse("https://[::1]:9443/a").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((t.host.as_str(), t.port), ("::1", 9443));
        assert_eq!(Target::parse("http://id.example.org/"), Err(Error::NotHttps));
        for bad in [
            "https://",
            "https:///path",
            "https://user:pw@example.org/",
            "https://id.example.org:0/",
            "https://id.example.org:x/",
            "https://id.example.org/a b",
        ] {
            assert!(matches!(Target::parse(bad), Err(Error::BadUrl(_))), "{bad}");
        }
    }
}
