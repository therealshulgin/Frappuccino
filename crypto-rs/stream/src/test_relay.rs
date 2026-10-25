//! A minimal HTTP/1.1-over-TLS server on loopback, for exercising the pinned
//! `DirectTls` client end to end in unit tests: a throwaway self-signed
//! certificate, pinned through the same extraction the verifier uses, one
//! request per connection, every request recorded.
//!
//! It parses only what the client sends (a request line, headers, a
//! `Content-Length` body) and answers with whatever the test's responder
//! returns. A body that ends before its `Content-Length` is recorded as
//! incomplete and gets no response, which is how a client abort looks from
//! the receiving side.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// One request as the server received it.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) complete: bool,
}

impl Recorded {
    /// Value of header `name`, compared case-insensitively.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What to answer.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    pub(crate) fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn with_body(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

type Responder = dyn Fn(&Recorded) -> Reply + Send + Sync;

/// A running server.
pub(crate) struct TestRelay {
    pub(crate) port: u16,
    pub(crate) pin: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl TestRelay {
    /// `https://127.0.0.1:<port>`.
    pub(crate) fn base_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Every request received so far.
    pub(crate) fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    /// A pinned rustls client config for this server.
    pub(crate) fn client_tls(&self) -> rustls::ClientConfig {
        let verifier =
            crate::pin::PinnedCertVerifier::with_pins_and_host(&[self.pin.as_str()], "127.0.0.1")
                .unwrap();
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
    }
}

/// Start a server answering with `respond`.
pub(crate) fn spawn(respond: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> TestRelay {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let pin = crate::pin::spki_pin_b64(cert_der.as_ref()).unwrap();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
    );
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let respond: Arc<Responder> = Arc::new(respond);
    let recorded = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let config = Arc::clone(&config);
            let respond = Arc::clone(&respond);
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || serve(stream, &config, &*respond, &recorded));
        }
    });
    TestRelay {
        port,
        pin,
        requests,
    }
}

fn serve(
    tcp: TcpStream,
    config: &Arc<rustls::ServerConfig>,
    respond: &Responder,
    recorded: &Mutex<Vec<Recorded>>,
) {
    let Ok(conn) = rustls::ServerConnection::new(Arc::clone(config)) else {
        return;
    };
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let Some(request) = read_request(&mut tls) else {
        return;
    };
    let complete = request.complete;
    recorded.lock().unwrap().push(request.clone());
    if !complete {
        return;
    }
    let reply = respond(&request);
    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
    for (name, value) in &reply.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    let _ = write!(head, "Content-Length: {}\r\n\r\n", reply.body.len());
    let _ = tls.write_all(head.as_bytes());
    let _ = tls.write_all(&reply.body);
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn read_request(tls: &mut impl Read) -> Option<Recorded> {
    let mut reader = BufReader::new(tls);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let declared: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = Vec::new();
    let _ = reader.by_ref().take(declared as u64).read_to_end(&mut body);
    Some(Recorded {
        complete: body.len() == declared,
        method,
        path,
        headers,
        body,
    })
}
