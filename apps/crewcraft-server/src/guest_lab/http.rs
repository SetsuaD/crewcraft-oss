//! One bounded HTTP/1.1 exchange on the lab listener's deadline-limited HTTPS stream.

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::Mutex;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crewcraft_proto::guest::GuestState;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::{GuestBearer, GuestEntrance, GuestError, GuestKnock, GuestPreview, GuestProof};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_HEAD: usize = 8 * 1024;
const MAX_FIELDS: usize = 32;
const MAX_BODY: usize = 4 * 1024;
const MAX_REPLY: usize = 2 * 1024;
const JSON: &str = "application/json";
const PAGE: &str = include_str!("lobby.html");
const SCRIPT: &str = include_str!("lobby.js");
const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const _: () = assert!(PAGE.len() <= 8 * 1024 && SCRIPT.len() <= 8 * 1024);

enum Problem {
    Malformed,
    Refused,
    LargeBody,
    LargeHead,
    RateLimited,
    Unavailable,
}

impl From<GuestError> for Problem {
    fn from(error: GuestError) -> Self {
        match error {
            GuestError::BadText => Self::Malformed,
            GuestError::RateLimited => Self::RateLimited,
            GuestError::MediaUnavailable | GuestError::Durable(_) => Self::Unavailable,
            _ => Self::Refused,
        }
    }
}

enum Route {
    Page,
    Script,
    Api(ApiRoute),
}

enum ApiRoute {
    Lookup,
    Knock,
    Status(Option<GuestProof>),
    Leave(Option<GuestProof>),
}

struct Head {
    route: Route,
    body_len: usize,
}

fn header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Result<Option<&'a [u8]>, Problem> {
    let mut values = headers.iter().filter(|field| field.name.eq_ignore_ascii_case(name)).map(|field| field.value);
    let value = values.next();
    if values.next().is_some() { Err(Problem::Malformed) } else { Ok(value) }
}

fn content_length(value: &[u8]) -> Result<usize, Problem> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(Problem::Malformed);
    }
    let value = std::str::from_utf8(value).map_err(|_| Problem::Malformed)?;
    let length = value.parse::<usize>().map_err(|_| Problem::LargeBody)?;
    if length > MAX_BODY { Err(Problem::LargeBody) } else { Ok(length) }
}

fn decode_proof(authorization: Option<&[u8]>) -> Option<GuestProof> {
    let (scheme, encoded) = authorization?.split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case(b"Bearer ") || encoded.len() != 64 {
        return None;
    }
    let mut raw = Zeroizing::new([0; 48]);
    if URL_SAFE_NO_PAD.decode_slice(encoded, &mut raw[..]).ok()? != raw.len() {
        return None;
    }
    let (meeting, rest) = raw.split_first_chunk::<8>()?;
    let (guest, bearer) = rest.split_first_chunk::<8>()?;
    Some(GuestProof { meeting: u64::from_be_bytes(*meeting), guest: u64::from_be_bytes(*guest), bearer: GuestBearer(bearer.try_into().ok()?) })
}

fn parse_head(bytes: &[u8], authority: &str, origin: &str) -> Result<Option<(Head, usize)>, Problem> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_FIELDS];
    let mut request = httparse::Request::new(&mut fields);
    let head_len = match request.parse(bytes) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) if bytes.len() < MAX_HEAD => return Ok(None),
        Ok(httparse::Status::Partial) | Err(httparse::Error::TooManyHeaders) => return Err(Problem::LargeHead),
        Err(_) => return Err(Problem::Malformed),
    };
    let head = &bytes[..head_len];
    if request.version != Some(1)
        || head.starts_with(b"\r\n")
        || head.split_inclusive(|byte| *byte == b'\n').any(|line| line.strip_suffix(b"\r\n").is_none_or(|text| text.contains(&b'\r')))
    {
        return Err(Problem::Malformed);
    }
    let fields = request.headers;
    if fields.iter().any(|field| {
        ["Transfer-Encoding", "Trailer", "Expect", "Upgrade"].iter().any(|name| field.name.eq_ignore_ascii_case(name))
            || (field.name.eq_ignore_ascii_case("Connection")
                && field.value.split(|byte| *byte == b',').any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade")))
    }) {
        return Err(Problem::Malformed);
    }
    let host = header(fields, "Host")?;
    let request_origin = header(fields, "Origin")?;
    let authorization = header(fields, "Authorization")?;
    let content_type = header(fields, "Content-Type")?;
    let length = header(fields, "Content-Length")?.map(content_length).transpose()?;
    if !host.is_some_and(|host| host.eq_ignore_ascii_case(authority.as_bytes())) {
        return Err(Problem::Malformed);
    }
    let route = match request.method {
        Some("GET") => {
            if length.unwrap_or_default() != 0 {
                return Err(Problem::Malformed);
            }
            match request.path {
                Some("/guest/") => Route::Page,
                Some("/guest/lobby.js") => Route::Script,
                _ => return Err(Problem::Refused),
            }
        }
        Some("POST") => {
            if request_origin != Some(origin.as_bytes()) || content_type != Some(JSON.as_bytes()) || length.is_none() {
                return Err(Problem::Malformed);
            }
            Route::Api(match request.path {
                Some("/v1/guest/lookup") => ApiRoute::Lookup,
                Some("/v1/guest/knock") => ApiRoute::Knock,
                Some("/v1/guest/status") => ApiRoute::Status(decode_proof(authorization)),
                Some("/v1/guest/leave") => ApiRoute::Leave(decode_proof(authorization)),
                _ => return Err(Problem::Refused),
            })
        }
        _ => return Err(Problem::Refused),
    };
    Ok(Some((Head { route, body_len: length.unwrap_or_default() }, head_len)))
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Invite(String);

impl Drop for Invite {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    code: Invite,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Knock {
    code: Invite,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

enum Request {
    Lookup(Lookup),
    Knock(Knock),
    Status(GuestProof),
    Leave(GuestProof),
}

fn json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Problem> {
    // Struct deserializers also accept positional arrays. The HTTP contract accepts JSON objects alone.
    if body.trim_ascii_start().first() != Some(&b'{') {
        return Err(Problem::Malformed);
    }
    serde_json::from_slice(body).map_err(|_| Problem::Malformed)
}

impl ApiRoute {
    fn request(self, body: &[u8]) -> Result<Request, Problem> {
        match self {
            Self::Lookup => Ok(Request::Lookup(json(body)?)),
            Self::Knock => Ok(Request::Knock(json(body)?)),
            Self::Status(proof) => {
                let Empty {} = json(body)?;
                Ok(Request::Status(proof.ok_or(Problem::Refused)?))
            }
            Self::Leave(proof) => {
                let Empty {} = json(body)?;
                Ok(Request::Leave(proof.ok_or(Problem::Refused)?))
            }
        }
    }
}

enum Reply {
    Preview(GuestPreview),
    Knock(GuestKnock),
    Status(GuestState),
    Left,
}

fn apply(request: Request, rooms: &Mutex<DurableServer>, peer: IpAddr, now: &dyn Fn() -> u64) -> Result<Reply, Problem> {
    let mut rooms = rooms.try_lock().map_err(|_| Problem::Unavailable)?;
    let mut entrance = rooms.guest_entrance(now);
    Ok(match request {
        Request::Lookup(input) => Reply::Preview(entrance.lookup(peer, &input.code.0)?),
        Request::Knock(input) => Reply::Knock(entrance.knock(peer, &input.code.0, &input.name)?),
        Request::Status(proof) => Reply::Status(entrance.status(peer, &proof)?.state),
        Request::Leave(proof) => {
            entrance.leave(peer, &proof)?;
            Reply::Left
        }
    })
}

fn state_name(state: GuestState) -> &'static str {
    match state {
        GuestState::Waiting => "waiting",
        GuestState::Admitted => "admitted",
        GuestState::Declined => "declined",
        GuestState::Removed => "removed",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewReply<'a> {
    title: &'a str,
    host_name: &'a str,
}

#[derive(Serialize)]
struct KnockReply<'a> {
    proof: &'a str,
    state: &'static str,
}

#[derive(Serialize)]
struct StatusReply {
    state: &'static str,
}

fn write_reply(stream: &mut impl Write, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Preview(preview) => write_json(stream, "200 OK", &PreviewReply { title: &preview.title, host_name: &preview.host_name }),
        Reply::Knock(knock) => {
            let mut raw = Zeroizing::new([0; 48]);
            raw[..8].copy_from_slice(&knock.proof.meeting.to_be_bytes());
            raw[8..16].copy_from_slice(&knock.proof.guest.to_be_bytes());
            raw[16..].copy_from_slice(&knock.proof.bearer.0);
            let proof = Zeroizing::new(URL_SAFE_NO_PAD.encode(&raw[..]));
            write_json(stream, "201 Created", &KnockReply { proof: &proof, state: state_name(knock.state) })
        }
        Reply::Status(state) => write_json(stream, "200 OK", &StatusReply { state: state_name(state) }),
        Reply::Left => respond(stream, "204 No Content", None, b"", false),
    }
}

fn write_json(stream: &mut impl Write, status: &str, value: &impl Serialize) -> io::Result<()> {
    if let Ok(bytes) = serde_json::to_vec(value) {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() <= MAX_REPLY {
            return respond(stream, status, Some(JSON), &bytes, false);
        }
    }
    write_problem(stream, Problem::Unavailable)
}

fn write_problem(stream: &mut impl Write, problem: Problem) -> io::Result<()> {
    let (status, body) = match problem {
        Problem::Malformed => ("400 Bad Request", br#"{"error":"invalid request"}"#.as_slice()),
        Problem::Refused => ("404 Not Found", br#"{"error":"unavailable"}"#.as_slice()),
        Problem::LargeBody => ("413 Content Too Large", br#"{"error":"body too large"}"#.as_slice()),
        Problem::LargeHead => ("431 Request Header Fields Too Large", br#"{"error":"headers too large"}"#.as_slice()),
        Problem::RateLimited => ("429 Too Many Requests", br#"{"error":"try again later"}"#.as_slice()),
        Problem::Unavailable => ("503 Service Unavailable", br#"{"error":"try again later"}"#.as_slice()),
    };
    respond(stream, status, Some(JSON), body, matches!(problem, Problem::RateLimited))
}

fn respond(stream: &mut impl Write, status: &str, content_type: Option<&str>, body: &[u8], retry: bool) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Security-Policy: {CSP}\r\n"
    )?;
    if let Some(content_type) = content_type {
        write!(stream, "Content-Type: {content_type}\r\nContent-Length: {}\r\n", body.len())?;
    }
    if retry {
        stream.write_all(b"Retry-After: 5\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}

pub(super) fn serve(
    stream: &mut (impl Read + Write),
    authority: &str,
    origin: &str,
    rooms: &Mutex<DurableServer>,
    peer: IpAddr,
    now: &dyn Fn() -> u64,
) -> io::Result<()> {
    let mut bytes = Zeroizing::new([0; MAX_HEAD + MAX_BODY + 1]);
    let mut used = 0;
    let (head, head_len) = loop {
        let count = stream.read(&mut bytes[used..MAX_HEAD])?;
        if count == 0 {
            return if used == 0 { Ok(()) } else { write_problem(stream, Problem::Malformed) };
        }
        used += count;
        match parse_head(&bytes[..used], authority, origin) {
            Ok(Some(parsed)) => break parsed,
            Ok(None) => {}
            Err(problem) => return write_problem(stream, problem),
        }
    };
    let end = head_len + head.body_len;
    while used < end {
        let count = stream.read(&mut bytes[used..=end])?;
        if count == 0 {
            return write_problem(stream, Problem::Malformed);
        }
        used += count;
    }
    if used != end {
        return write_problem(stream, Problem::Malformed);
    }

    match head.route {
        Route::Page => respond(stream, "200 OK", Some("text/html; charset=utf-8"), PAGE.as_bytes(), false),
        Route::Script => respond(stream, "200 OK", Some("text/javascript; charset=utf-8"), SCRIPT.as_bytes(), false),
        Route::Api(route) => match route.request(&bytes[head_len..end]).and_then(|request| apply(request, rooms, peer, now)) {
            Ok(reply) => write_reply(stream, reply),
            Err(problem) => write_problem(stream, problem),
        },
    }
}
