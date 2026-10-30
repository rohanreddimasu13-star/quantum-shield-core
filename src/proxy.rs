//! Quantum Shield's experimental Rust reverse-proxy engine.
//!
//! HTTP and supplied-certificate HTTPS have explicit listener safeguards. ACME
//! HTTP-01 defaults to Let's Encrypt staging and requires an explicit public
//! listener acknowledgement; production ACME additionally requires a second
//! explicit acknowledgement. This is a production-hardening candidate, not an
//! independently audited or universally production-ready gateway.

use std::convert::Infallible;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, UPGRADE,
    USER_AGENT,
};
use http::uri::Authority;
use http::{HeaderMap, Request, Response, StatusCode, Uri};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls_acme::tower::TowerHttp01ChallengeService;
use rustls_acme::{caches::DirCache, AcmeConfig, UseChallenge};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
use tower_service::Service;
use url::Url;

use crate::config::{Config, SiteConfig};

type ProxyBody = UnsyncBoxBody<Bytes, hyper::Error>;
type BodyFrame = std::result::Result<Frame<Bytes>, io::Error>;
type ProxyClient = Client<HttpConnector, PumpedBody>;

/// Minimal Prometheus metrics, active only with `--features prometheus`.
/// The scrape endpoint is loopback-only and never exposed to public clients.
#[cfg(feature = "prometheus")]
mod metrics {
    use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};
    use std::sync::OnceLock;

    struct Metrics {
        registry: Registry,
        requests: IntCounterVec,
    }

    fn metrics() -> &'static Metrics {
        static METRICS: OnceLock<Metrics> = OnceLock::new();
        METRICS.get_or_init(|| {
            let registry = Registry::new();
            let requests = IntCounterVec::new(
                Opts::new(
                    "quantum_shield_http_responses_total",
                    "HTTP responses emitted by the Quantum Shield proxy, by status.",
                ),
                &["status"],
            )
            .expect("valid static metric descriptor");
            registry
                .register(Box::new(requests.clone()))
                .expect("metric registration cannot fail for a fresh registry");
            Metrics { registry, requests }
        })
    }

    pub(super) fn observe(status: u16) {
        metrics()
            .requests
            .with_label_values(&[&status.to_string()])
            .inc();
    }

    pub(super) fn render() -> String {
        let mut output = Vec::new();
        let encoder = TextEncoder::new();
        if encoder
            .encode(&metrics().registry.gather(), &mut output)
            .is_err()
        {
            return String::from("# metrics encoding failed\n");
        }
        String::from_utf8_lossy(&output).into_owned()
    }
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedStream = Box<dyn AsyncStream>;

/// A bounded channel body separates reading the untrusted client upload from
/// sending it upstream. The producer continues counting bytes even if an
/// upstream responds early and drops its body receiver.
struct PumpedBody {
    receiver: mpsc::Receiver<BodyFrame>,
    end_polled: Arc<AtomicBool>,
    known_empty: bool,
    expected_content_length: Option<u64>,
    forwarded_bytes: u64,
}

impl HttpBody for PumpedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Option<BodyFrame>> {
        let this = self.get_mut();
        if this.known_empty {
            this.end_polled.store(true, Ordering::Release);
            return Poll::Ready(None);
        }
        let polled = Pin::new(&mut this.receiver).poll_recv(context);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(expected), Some(data)) =
                    (this.expected_content_length, frame.data_ref())
                {
                    this.forwarded_bytes = this.forwarded_bytes.saturating_add(data.len() as u64);
                    if expected > 0 && this.forwarded_bytes == expected {
                        // With Content-Length framing, Hyper may stop polling
                        // once the declared byte count has been consumed. It
                        // does not necessarily poll a separate EOF frame.
                        this.end_polled.store(true, Ordering::Release);
                    }
                }
            }
            Poll::Ready(None) => {
                this.end_polled.store(true, Ordering::Release);
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.known_empty
    }

    fn size_hint(&self) -> SizeHint {
        if self.known_empty {
            let mut hint = SizeHint::default();
            hint.set_exact(0);
            hint
        } else {
            SizeHint::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestBodyOutcome {
    /// The body stream completed without yielding any frames (ordinary bodyless request).
    CompleteEmpty,
    /// At least one frame was received and the body completed.
    Complete,
    TooLarge,
    InvalidBody,
    IdleTimeout,
    TotalTimeout,
}

/// Reads the incoming body independently of the upstream request future.
/// The bounded channel supplies back-pressure. If the upstream stops polling
/// its body, the producer keeps draining/counting the client body until EOF,
/// an error, or the byte/time limits; it never buffers the entire upload.
async fn pump_request_body<B>(
    mut incoming: B,
    sender: mpsc::Sender<BodyFrame>,
    max_bytes: usize,
) -> RequestBodyOutcome
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Display + Send + 'static,
{
    let mut sender = Some(sender);
    let mut observed_bytes = 0usize;
    let mut saw_frame = false;

    loop {
        let frame = match tokio::time::timeout(REQUEST_BODY_IDLE_TIMEOUT, incoming.frame()).await {
            Err(_) => {
                notify_body_error(&mut sender, "client request body idle timeout");
                return RequestBodyOutcome::IdleTimeout;
            }
            Ok(None) => {
                return if saw_frame {
                    RequestBodyOutcome::Complete
                } else {
                    RequestBodyOutcome::CompleteEmpty
                };
            }
            Ok(Some(Err(error))) => {
                eprintln!("could not read client request body: {error}");
                notify_body_error(&mut sender, "invalid client request body");
                return RequestBodyOutcome::InvalidBody;
            }
            Ok(Some(Ok(frame))) => {
                saw_frame = true;
                frame
            }
        };

        if let Some(data) = frame.data_ref() {
            let Some(next_size) = observed_bytes.checked_add(data.len()) else {
                notify_body_error(&mut sender, "request body size overflow");
                return RequestBodyOutcome::TooLarge;
            };
            if next_size > max_bytes {
                notify_body_error(&mut sender, "request body limit exceeded");
                return RequestBodyOutcome::TooLarge;
            }
            observed_bytes = next_size;
        }

        // If the upstream request body consumer has disappeared, or is not
        // taking data, stop forwarding but keep reading only to enforce the
        // client-side byte cap. The handler will not relay an early response.
        if let Some(active_sender) = sender.as_ref() {
            let send_result =
                tokio::time::timeout(BODY_CHANNEL_SEND_TIMEOUT, active_sender.send(Ok(frame)))
                    .await;
            if !matches!(send_result, Ok(Ok(()))) {
                sender = None;
            }
        }
    }
}

fn notify_body_error(sender: &mut Option<mpsc::Sender<BodyFrame>>, message: &'static str) {
    if let Some(active_sender) = sender.take() {
        let error = io::Error::new(io::ErrorKind::InvalidData, message);
        // Best effort only: if the bounded queue is full, dropping its sender
        // still terminates the stream. RequestBodyOutcome remains authoritative.
        let _ = active_sender.try_send(Err(error));
    }
}

const MAX_ACTIVE_CONNECTIONS: usize = 128;
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_HEADER_COUNT: usize = 64;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_BODY_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const BODY_CHANNEL_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_CHANNEL_CAPACITY: usize = 4;
const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const UPSTREAM_IDLE_POOL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_IDLE_UPSTREAM_CONNECTIONS_PER_HOST: usize = 16;
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);
const OVER_CAPACITY_REPLY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nRetry-After: 1\r\nContent-Length: 24\r\n\r\nQuantum Shield is busy.\n";
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

#[derive(Clone, Debug)]
struct Route {
    domain: String,
    upstream: String,
}

impl TryFrom<SiteConfig> for Route {
    type Error = anyhow::Error;

    fn try_from(site: SiteConfig) -> Result<Self> {
        // Config validation happens before this conversion. Parse once at startup
        // as an additional guard, not once per incoming request.
        let upstream = Url::parse(&site.upstream)
            .with_context(|| format!("invalid upstream for site {}", site.id))?;
        if upstream.scheme() != "http" || upstream.host_str().is_none() || upstream.port().is_none()
        {
            bail!("site {} has an unsupported upstream URL", site.id);
        }

        Ok(Self {
            domain: site.domain.trim_end_matches('.').to_ascii_lowercase(),
            upstream: site.upstream.trim_end_matches('/').to_owned(),
        })
    }
}

/// Start the HTTP-only prototype. It intentionally refuses non-loopback
/// listener addresses so unfinished code cannot accidentally become public.
pub async fn serve_http(config: Config, listen: SocketAddr) -> Result<()> {
    serve_with_transport(config, listen, None, false).await
}

/// Start the HTTPS prototype using an operator-supplied PEM certificate and
/// private key. Non-loopback binding requires explicit opt-in. ACME
/// issuance/renewal is deliberately a separate component.
pub async fn serve_https(
    config: Config,
    listen: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    allow_public_listener: bool,
) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_public_listener {
        bail!("HTTPS public listeners are disabled unless the operator explicitly passes --allow-public-listener");
    }
    // Validate the initial certificate/key pair synchronously before the listener
    // is opened, then install a file-watched resolver. Valid certificate updates
    // are picked up for new handshakes; existing TLS connections remain alive.
    let tls_config = load_tls_server_config_watched(cert_path, key_path).await?;
    eprintln!(
        "TLS certificate hot reload enabled for {} and {}",
        cert_path.display(),
        key_path.display()
    );
    serve_with_transport(config, listen, Some(tls_config), allow_public_listener).await
}

async fn load_tls_server_config_watched(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>> {
    // Install the same AWS-LC provider used by the hot-reload resolver before
    // parsing/building any Rustls configuration.
    tls_hot_reload::install_crypto_provider();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let _validated = load_tls_server_config(cert_path, key_path)?;
    let watched_key = tls_hot_reload::CertifiedKeyWatched::new(
        key_path.to_string_lossy().into_owned(),
        cert_path.to_string_lossy().into_owned(),
    )
    .await
    .with_context(|| {
        format!(
            "could not start certificate watcher for {} and {}",
            cert_path.display(),
            key_path.display()
        )
    })?;

    let strict_pqc = quantum_shield_pqc_strict_mode()?;
    let provider = quantum_shield_crypto_provider_for_mode(strict_pqc)?;
    let builder = rustls::ServerConfig::builder_with_provider(provider);
    let builder = if strict_pqc {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .context("failed to configure TLS protocol versions")?;

    let mut server_config = with_client_auth(builder)?.with_cert_resolver(watched_key);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server_config))
}

/// Feature-gated builder step that enforces mutual TLS. With `mTls` enabled the
/// proxy refuses to start unless a CA bundle is configured and every client
/// certificate validates against it. Without the feature this is a no-op.
#[cfg(feature = "mTls")]
fn with_client_auth(
    builder: rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>> {
    let path = std::env::var("QUANTUM_SHIELD_MTLS_CA").context(
        "the mTls feature requires QUANTUM_SHIELD_MTLS_CA to name a PEM client-CA bundle",
    )?;
    let verifier = mtls_client_verifier_from_bundle(Path::new(&path))?;
    Ok(builder.with_client_cert_verifier(verifier))
}

#[cfg(feature = "mTls")]
fn mtls_client_verifier_from_bundle(
    path: &Path,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    use rustls::RootCertStore;

    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| {
            format!(
                "could not open mutual-TLS client CA bundle {}",
                path.display()
            )
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "could not parse mutual-TLS client CA bundle {}",
                path.display()
            )
        })?;
    if certs.is_empty() {
        bail!(
            "mutual-TLS client CA bundle {} contains no PEM certificates",
            path.display()
        );
    }

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).with_context(|| {
            format!(
                "invalid mutual-TLS client CA certificate in {}",
                path.display()
            )
        })?;
    }
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("could not build mutual-TLS client certificate verifier")
}

#[cfg(not(feature = "mTls"))]
fn with_client_auth(
    builder: rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>> {
    Ok(builder.with_no_client_auth())
}

/// Strict hybrid post-quantum key exchange is the default.
/// Set QUANTUM_SHIELD_PQC_MODE=prefer only for explicit compatibility testing.
fn quantum_shield_pqc_strict_from_value(value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("strict") => Ok(true),
        Some("prefer") => Ok(false),
        Some(_) => anyhow::bail!("QUANTUM_SHIELD_PQC_MODE must be 'prefer' or 'strict'"),
    }
}

fn quantum_shield_pqc_strict_mode() -> anyhow::Result<bool> {
    match std::env::var("QUANTUM_SHIELD_PQC_MODE") {
        Ok(value) => quantum_shield_pqc_strict_from_value(Some(&value)),
        Err(std::env::VarError::NotPresent) => quantum_shield_pqc_strict_from_value(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("QUANTUM_SHIELD_PQC_MODE must be valid Unicode")
        }
    }
}

/// Build an AWS-LC provider. Strict mode exposes only X25519MLKEM768.
fn quantum_shield_crypto_provider_for_mode(
    strict_pqc: bool,
) -> anyhow::Result<std::sync::Arc<rustls::crypto::CryptoProvider>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS.to_vec();

    if strict_pqc {
        // The ACME incoming API uses safe protocol defaults. Remove TLS 1.2
        // suites here so that its strict-mode listener cannot complete TLS 1.2.
        provider
            .cipher_suites
            .retain(|suite| suite.version() == &rustls::version::TLS13);

        if provider.cipher_suites.is_empty() {
            anyhow::bail!("strict PQC mode requires TLS 1.3 cipher suites");
        }

        let hybrid = provider
            .kx_groups
            .iter()
            .copied()
            .find(|group| format!("{:?}", group.name()) == "X25519MLKEM768")
            .ok_or_else(|| anyhow::anyhow!(
                "strict PQC mode requires the X25519MLKEM768 key-exchange group,                  which is unavailable in this AWS-LC provider"
            ))?;

        provider.kx_groups = vec![hybrid];
    }

    Ok(std::sync::Arc::new(provider))
}

#[cfg(test)]
fn quantum_shield_crypto_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    quantum_shield_crypto_provider_for_mode(false)
        .expect("AWS-LC provider must offer its configured key-exchange groups")
}

fn load_tls_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>> {
    // Ensure the default crypto provider (aws-lc-rs with prefer-post-quantum)
    // is installed and its key-exchange groups are used.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certificates = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| {
            format!(
                "could not open TLS certificate file {}",
                cert_path.display()
            )
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "could not parse PEM certificates from {}",
                cert_path.display()
            )
        })?;
    if certificates.is_empty() {
        bail!(
            "TLS certificate file {} contains no PEM certificates",
            cert_path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(key_path).with_context(|| {
            format!(
                "could not inspect TLS private key file {}",
                key_path.display()
            )
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "TLS private key {} is accessible to group/others; restrict its permissions (for example chmod 600)",
                key_path.display()
            );
        }
    }

    let private_key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!(
            "could not parse PEM private key from {}; file must contain a supported unencrypted PEM private key",
            key_path.display()
        ))?;

    let strict_pqc = quantum_shield_pqc_strict_mode()?;
    let provider = quantum_shield_crypto_provider_for_mode(strict_pqc)?;
    let builder = rustls::ServerConfig::builder_with_provider(provider);
    let builder = if strict_pqc {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .context("failed to configure TLS protocol versions")?;

    let mut server_config = with_client_auth(builder)?
        .with_single_cert(certificates, private_key)
        .context("TLS certificate and private key are invalid or do not match")?;
    // This component serves HTTP/1.1 only. Do not advertise h2 until a proper
    // HTTP/2 connection path is implemented and tested.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server_config))
}

/// Validate that the supplied certificate chain and unencrypted private key
/// can be loaded together. The Docker Compose adapter calls this before
/// generating deployment files or starting any container.
pub(crate) fn validate_tls_material(cert_path: &Path, key_path: &Path) -> Result<()> {
    let _validated_config = load_tls_server_config(cert_path, key_path)?;
    Ok(())
}

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_with_transport(
    config: Config,
    listen: SocketAddr,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    allow_public_listener: bool,
) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_public_listener {
        bail!("this listener may only bind to loopback unless public binding is explicitly acknowledged");
    }

    let tls_enabled = tls_config.is_some();
    let strict_pqc = if tls_enabled {
        quantum_shield_pqc_strict_mode()?
    } else {
        false
    };
    let routes = config
        .sites
        .into_iter()
        .map(Route::try_from)
        .collect::<Result<Vec<_>>>()?;
    let routes = Arc::new(routes);

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("could not bind local test listener at {listen}"))?;
    let actual_addr = listener.local_addr()?;

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
    connector.enforce_http(true);

    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_max_idle_per_host(MAX_IDLE_UPSTREAM_CONNECTIONS_PER_HOST)
        .pool_idle_timeout(UPSTREAM_IDLE_POOL_TIMEOUT)
        .pool_timer(TokioTimer::new());
    let client: ProxyClient = client_builder.build(connector);

    let connection_slots = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let mut tasks = JoinSet::new();

    println!(
        "Quantum Shield {} engine prototype",
        if tls_enabled {
            "HTTPS"
        } else {
            "HTTP hardening"
        }
    );
    println!(
        "Listening on: {}://{actual_addr}",
        if tls_enabled { "https" } else { "http" }
    );
    println!("Configured routes  : {}", routes.len());
    println!("Active connection cap: {MAX_ACTIVE_CONNECTIONS}");
    println!("Request headers      : max {MAX_REQUEST_HEADER_BYTES} bytes / {MAX_REQUEST_HEADER_COUNT} fields");
    println!(
        "Header read timeout  : {} seconds",
        REQUEST_HEADER_TIMEOUT.as_secs()
    );
    println!(
        "Upstream connect timeout: {} seconds",
        UPSTREAM_CONNECT_TIMEOUT.as_secs()
    );
    println!(
        "Request-body idle timeout: {} seconds",
        REQUEST_BODY_IDLE_TIMEOUT.as_secs()
    );
    println!(
        "Request-body total timeout: {} seconds",
        REQUEST_BODY_TOTAL_TIMEOUT.as_secs()
    );
    println!(
        "Upstream request timeout: {} seconds",
        UPSTREAM_REQUEST_TIMEOUT.as_secs()
    );
    if tls_enabled {
        println!("TLS: Rustls with the AWS-LC cryptographic provider");
        let strict_pqc = quantum_shield_pqc_strict_mode()?;
        if strict_pqc {
            println!(
                "PQC policy: STRICT X25519MLKEM768; TLS 1.3 only; classical fallback disabled"
            );
        } else {
            println!("PQC policy: hybrid preferred; classical fallback allowed for compatibility");
        }
        println!("ACME: not implemented; certificate/key supplied by operator");
    } else {
        println!("TLS/ACME             : not implemented");
    }
    println!(
        "WebSockets           : disabled by default; frame-level inspection is not implemented"
    );
    println!(
        "Request body cap: {} MiB (incremental, without full-body buffering)",
        MAX_REQUEST_BODY_BYTES / (1024 * 1024)
    );
    println!("Press Ctrl+C to stop. This is a local test server, not production-ready.");

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl+C")?;
                println!("Shutdown requested; no new connections will be accepted.");
                break;
            }
            accepted = listener.accept() => {
                let (tcp_stream, remote_addr) = accepted.context("failed to accept local connection")?;
                let permit = match try_connection_slot(&connection_slots) {
                    Some(permit) => permit,
                    None => {
                        // Never send a plaintext HTTP overload response to a TLS client.
                        if tls_enabled {
                            drop(tcp_stream);
                        } else {
                            reject_over_capacity(tcp_stream).await;
                        }
                        continue;
                    }
                };
                let client = client.clone();
                let routes = Arc::clone(&routes);
                let connection_tls_config = tls_config.clone();
                let connection_strict_pqc = strict_pqc;

                tasks.spawn(async move {
                    let _connection_permit = permit;
                    let io_stream: BoxedStream = if let Some(config) = connection_tls_config {
                        let acceptor = TlsAcceptor::from(config);
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                            Ok(Ok(tls_stream)) => {
                                let server_connection = tls_stream.get_ref().1;
                                let version = server_connection.protocol_version()
                                    .map(|version| format!("{version:?}"))
                                    .unwrap_or_else(|| "unknown".to_owned());
                                let key_exchange = server_connection.negotiated_key_exchange_group()
                                    .map(|group| format!("{:?}", group.name()))
                                    .unwrap_or_else(|| "unknown/resumed".to_owned());
                                let cipher_suite = server_connection.negotiated_cipher_suite()
                                    .map(|suite| format!("{:?}", suite.suite()))
                                    .unwrap_or_else(|| "unknown".to_owned());
                                eprintln!("TLS handshake complete: version={version}, cipher_suite={cipher_suite}, key_exchange={key_exchange}");
                                if connection_strict_pqc && key_exchange != "X25519MLKEM768" {
                                    eprintln!("PQC STRICT policy rejected connection from {remote_addr}: negotiated key exchange was {key_exchange}");
                                    return;
                                }
                                Box::new(tls_stream)
                            }
                            Ok(Err(error)) => {
                                eprintln!("TLS handshake failed from {remote_addr}: {error}");
                                return;
                            }
                            Err(_) => {
                                eprintln!("TLS handshake timed out from {remote_addr}");
                                return;
                            }
                        }
                    } else {
                        Box::new(tcp_stream)
                    };
                    let client_proto: &'static str = if tls_enabled { "https" } else { "http" };
                    serve_proxy_connection(io_stream, client, routes, remote_addr, client_proto).await;
                });
            }
            Some(completed) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = completed {
                    eprintln!("connection task failed: {error}");
                }
            }
        }
    }

    let draining = drain_connections(&mut tasks);
    if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, draining)
        .await
        .is_err()
    {
        let remaining = tasks.len();
        eprintln!("Grace period expired; aborting {remaining} remaining local connection task(s).");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    } else {
        println!("Active connections drained cleanly.");
    }

    Ok(())
}

/// Validate ACME domain, contact, and cache inputs without network or filesystem I/O.
fn validate_acme_inputs(config: &Config, email: &str, cache_dir: &Path) -> Result<Vec<String>> {
    validate_acme_email(email)?;
    if config.sites.is_empty() {
        bail!("at least one site is required for ACME");
    }
    let mut domains = Vec::with_capacity(config.sites.len());
    for site in &config.sites {
        validate_acme_domain(&site.domain)?;
        domains.push(site.domain.trim_end_matches('.').to_ascii_lowercase());
    }
    domains.sort();
    domains.dedup();
    if domains.len() != config.sites.len() {
        bail!("duplicate ACME domains are not allowed");
    }
    if !cache_dir.is_absolute() {
        bail!("ACME cache directory must be an absolute path");
    }
    Ok(domains)
}

/// Check ACME staging prerequisites without binding sockets, creating files,
/// making DNS queries, or contacting the ACME service.
pub fn acme_staging_preflight(config: &Config, email: &str, cache_dir: &Path) -> Result<()> {
    let domains = validate_acme_inputs(config, email, cache_dir)?;
    println!("QUANTUM SHIELD ACME PREFLIGHT");
    println!("======================================");
    println!("Mode             : Let's Encrypt staging only (the production directory is used only by serve-acme-http01 with explicit acknowledgements)");
    println!("Directory        : https://acme-staging-v02.api.letsencrypt.org/directory");
    println!("Domains          : {}", domains.join(", "));
    println!("Contact          : {email}");
    println!("Persistent cache : {}", cache_dir.display());
    println!("Challenge        : TLS-ALPN-01; public TCP/443 must reach the server");
    println!();
    println!("NOT CHECKED: domain ownership, public A/AAAA DNS, NAT/firewall/port forwarding, upstream health, or certificate issuance.");
    println!("SAFE PREFLIGHT: no sockets opened, no files created, no DNS lookups, no ACME requests, no system changes.");
    Ok(())
}

/// Run a Let's Encrypt staging-only TLS-ALPN-01 proxy. This requires explicit
/// public-listener acknowledgement and is not a production certificate path.
/// External TCP/443 must reach this listener directly or through port forwarding.
pub async fn serve_acme_staging(
    config: Config,
    listen: SocketAddr,
    email: &str,
    cache_dir: &Path,
    allow_public_listener: bool,
) -> Result<()> {
    if !allow_public_listener {
        bail!("ACME staging opens a non-loopback service; review the exposure risk and pass --allow-public-listener explicitly to continue");
    }
    if listen.ip().is_loopback() {
        bail!("ACME TLS-ALPN-01 validation requires external reachability; bind to a LAN/public interface (not loopback), and route external TCP port 443 to this listener");
    }
    let domains = validate_acme_inputs(&config, email, cache_dir)?;
    if cache_dir.exists() {
        let metadata = std::fs::symlink_metadata(cache_dir).with_context(|| {
            format!("could not inspect ACME cache path {}", cache_dir.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "ACME cache path must be a real directory, not a symlink or regular file: {}",
                cache_dir.display()
            );
        }
    }
    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "could not create ACME cache directory {}",
            cache_dir.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(cache_dir).with_context(|| {
        format!(
            "could not inspect ACME cache directory {}",
            cache_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "ACME cache path must be a real directory: {}",
            cache_dir.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "could not restrict ACME cache directory permissions at {}",
                    cache_dir.display()
                )
            },
        )?;
    }

    let routes = config
        .sites
        .into_iter()
        .map(Route::try_from)
        .collect::<Result<Vec<_>>>()?;
    let routes = Arc::new(routes);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("could not bind ACME staging listener at {listen}"))?;
    let actual_addr = listener.local_addr()?;

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
    connector.enforce_http(true);
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_max_idle_per_host(MAX_IDLE_UPSTREAM_CONNECTIONS_PER_HOST)
        .pool_idle_timeout(UPSTREAM_IDLE_POOL_TIMEOUT)
        .pool_timer(TokioTimer::new());
    let client: ProxyClient = client_builder.build(connector);

    let connection_slots = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let mut tasks = JoinSet::new();
    let acme_contact = format!("mailto:{email}");
    // This version is intentionally hard-wired to the official staging directory.
    // There is no CLI flag or code path that switches this command to production ACME.
    let acme_state = AcmeConfig::new(domains.clone())
        .contact_push(acme_contact)
        .cache(DirCache::new(cache_dir.to_path_buf()))
        .directory("https://acme-staging-v02.api.letsencrypt.org/directory")
        .state();

    // ACME TLS-ALPN validation uses the library's dedicated challenge acceptor.
    // Ordinary TLS traffic uses the explicit Quantum Shield provider below.
    #[allow(deprecated)]
    let acme_acceptor = acme_state.acceptor();
    let incoming = rustls_acme::Incoming::new_with_provider(
        rustls_acme::tokio::TokioIncomingTcpWrapper::from(TcpListenerStream::new(listener)),
        acme_state,
        acme_acceptor,
        vec![b"http/1.1".to_vec()],
        quantum_shield_crypto_provider_for_mode(quantum_shield_pqc_strict_mode()?)?,
    );
    let mut tls_incoming = rustls_acme::tokio::TokioIncoming::from(incoming);

    println!("Quantum Shield ACME STAGING prototype");
    println!("Listener       : {actual_addr}");
    println!("ACME directory : https://acme-staging-v02.api.letsencrypt.org/directory");
    println!("Domains        : {}", domains.join(", "));
    println!("Contact        : {email}");
    println!(
        "Persistent cache: {} (directory mode 0700 on Unix)",
        cache_dir.display()
    );
    println!("Challenge      : TLS-ALPN-01; external TCP/443 must reach this listener");
    println!("Mode           : staging only; staging certificates are not publicly trusted");
    println!("WARNING        : this experimental proxy is externally reachable. Use a disposable test upstream only; not production-ready.");
    println!("Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl+C")?;
                println!("Shutdown requested; no new ACME/TLS connections will be accepted.");
                break;
            }
            incoming = tls_incoming.next() => {
                match incoming {
                    Some(Ok(tls_stream)) => {
                        let remote_addr = match tls_stream.get_ref().get_ref().0.get_ref().peer_addr() {
                            Ok(address) => address,
                            Err(error) => {
                                eprintln!("could not read remote address for ACME TLS connection: {error}");
                                drop(tls_stream);
                                continue;
                            }
                        };
                        let server_connection = tls_stream.get_ref().get_ref().1;
                        let version = server_connection.protocol_version()
                            .map(|value| format!("{value:?}"))
                            .unwrap_or_else(|| "unknown".to_owned());
                        let key_exchange = server_connection.negotiated_key_exchange_group()
                            .map(|group| format!("{:?}", group.name()))
                            .unwrap_or_else(|| "unknown/resumed".to_owned());
                        let cipher_suite = server_connection.negotiated_cipher_suite()
                            .map(|suite| format!("{:?}", suite.suite()))
                            .unwrap_or_else(|| "unknown".to_owned());
                        eprintln!("ACME TLS connection: peer={remote_addr}, version={version}, cipher_suite={cipher_suite}, key_exchange={key_exchange}");

                        let permit = match try_connection_slot(&connection_slots) {
                            Some(permit) => permit,
                            None => {
                                eprintln!("dropping ACME TLS connection from {remote_addr}: active connection limit reached");
                                drop(tls_stream);
                                continue;
                            }
                        };
                        let client = client.clone();
                        let routes = Arc::clone(&routes);
                        tasks.spawn(async move {
                            let _connection_permit = permit;
                            serve_proxy_connection(Box::new(tls_stream), client, routes, remote_addr, "https").await;
                        });
                    }
                    Some(Err(error)) => {
                        eprintln!("ACME staging accept/challenge error: {error:?}");
                    }
                    None => bail!("ACME incoming stream ended unexpectedly"),
                }
            }
            Some(completed) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = completed {
                    eprintln!("ACME connection task failed: {error}");
                }
            }
        }
    }

    let draining = drain_connections(&mut tasks);
    if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, draining)
        .await
        .is_err()
    {
        let remaining = tasks.len();
        eprintln!("Grace period expired; aborting {remaining} remaining ACME connection task(s).");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    } else {
        println!("Active ACME connections drained cleanly.");
    }
    Ok(())
}

/// Run an HTTP-01 ACME reverse proxy. Staging is the default; production
/// issuance requires a second explicit acknowledgement. The ACME incoming
/// stream is continuously polled, which drives certificate acquisition and renewal.
#[allow(clippy::too_many_arguments)]
pub async fn serve_acme_http01(
    config: Config,
    http_listen: SocketAddr,
    https_listen: SocketAddr,
    email: &str,
    cache_dir: &Path,
    production: bool,
    allow_public_listener: bool,
    acknowledge_production_issuance: bool,
) -> Result<()> {
    if !allow_public_listener {
        bail!("ACME HTTP-01 requires public reachability; review the exposed listeners and pass --allow-public-listener explicitly");
    }
    if http_listen.ip().is_loopback() || https_listen.ip().is_loopback() {
        bail!("HTTP-01 validation requires externally reachable listeners; bind to a LAN/public interface and route public TCP/80 and TCP/443 to these ports");
    }
    if http_listen.port() == https_listen.port() {
        bail!("HTTP and HTTPS listeners must use different ports");
    }
    if production && !acknowledge_production_issuance {
        bail!("production certificate issuance requires both --production and --acknowledge-production-issuance; validate with staging first");
    }
    let domains = validate_acme_inputs(&config, email, cache_dir)?;
    prepare_acme_cache(cache_dir)?;

    let routes = Arc::new(
        config
            .sites
            .into_iter()
            .map(Route::try_from)
            .collect::<Result<Vec<_>>>()?,
    );
    // Bind both ports before beginning ACME requests so an unavailable listener
    // cannot leave a half-configured process issuing certificates.
    let http_listener = TcpListener::bind(http_listen)
        .await
        .with_context(|| format!("could not bind HTTP-01 listener at {http_listen}"))?;
    let https_listener = TcpListener::bind(https_listen)
        .await
        .with_context(|| format!("could not bind HTTPS/ACME listener at {https_listen}"))?;
    let http_actual = http_listener.local_addr()?;
    let https_actual = https_listener.local_addr()?;

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
    connector.enforce_http(true);
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_max_idle_per_host(MAX_IDLE_UPSTREAM_CONNECTIONS_PER_HOST)
        .pool_idle_timeout(UPSTREAM_IDLE_POOL_TIMEOUT)
        .pool_timer(TokioTimer::new());
    let client: ProxyClient = client_builder.build(connector);

    let connection_slots = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let mut tasks = JoinSet::new();
    let contact = format!("mailto:{email}");
    let acme_state = AcmeConfig::new(domains.clone())
        .contact_push(contact)
        .cache(DirCache::new(cache_dir.to_path_buf()))
        .directory_lets_encrypt(production)
        .challenge_type(UseChallenge::Http01)
        .state();

    // The HTTP-01 service shares the ACME resolver. Keep the state inside the
    // incoming stream so issuance and renewals continue to be polled.
    let challenge_service = acme_state.http01_challenge_tower_service();
    #[allow(deprecated)]
    let acme_acceptor = acme_state.acceptor();
    let incoming = rustls_acme::Incoming::new_with_provider(
        rustls_acme::tokio::TokioIncomingTcpWrapper::from(TcpListenerStream::new(https_listener)),
        acme_state,
        acme_acceptor,
        vec![b"http/1.1".to_vec()],
        quantum_shield_crypto_provider_for_mode(quantum_shield_pqc_strict_mode()?)?,
    );
    let mut tls_incoming = rustls_acme::tokio::TokioIncoming::from(incoming);

    println!("Quantum Shield ACME HTTP-01 proxy");
    println!("HTTP listener   : {http_actual} (challenges + 308 redirects)");
    println!("HTTPS listener  : {https_actual}");
    println!("Domains         : {}", domains.join(", "));
    println!(
        "ACME directory  : {}",
        if production {
            "Let's Encrypt production"
        } else {
            "Let's Encrypt staging"
        }
    );
    println!(
        "Persistent cache: {} (restricted directory permissions on Unix)",
        cache_dir.display()
    );
    println!("Certificate lifecycle: rustls-acme is polled by the incoming TLS stream; cached account/certificate state persists across restarts");
    println!(
        "Logging: use Docker Compose rotation limits in generated deployments (10 MiB x 3 files)"
    );
    println!("WARNING: public listeners require DNS and firewall routing for TCP/80 and TCP/443; staging certificates are not trusted by browsers.");

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl+C")?;
                println!("Shutdown requested; no new HTTP/TLS connections will be accepted.");
                break;
            }
            accepted = http_listener.accept() => {
                let (stream, remote_addr) = accepted.context("failed to accept HTTP connection")?;
                let permit = match try_connection_slot(&connection_slots) {
                    Some(permit) => permit,
                    None => { reject_over_capacity(stream).await; continue; }
                };
                let service = challenge_service.clone();
                let routes = Arc::clone(&routes);
                tasks.spawn(async move {
                    let _connection_permit = permit;
                    serve_http01_connection(Box::new(stream), service, routes, remote_addr).await;
                });
            }
            incoming = tls_incoming.next() => {
                match incoming {
                    Some(Ok(tls_stream)) => {
                        let remote_addr = match tls_stream.get_ref().get_ref().0.get_ref().peer_addr() {
                            Ok(address) => address,
                            Err(error) => {
                                eprintln!("could not read peer address for ACME HTTPS connection: {error}");
                                drop(tls_stream);
                                continue;
                            }
                        };
                        let server_connection = tls_stream.get_ref().get_ref().1;
                        let version = server_connection.protocol_version()
                            .map(|value| format!("{value:?}"))
                            .unwrap_or_else(|| "unknown".to_owned());
                        let key_exchange = server_connection.negotiated_key_exchange_group()
                            .map(|group| format!("{:?}", group.name()))
                            .unwrap_or_else(|| "unknown/resumed".to_owned());
                        let cipher_suite = server_connection.negotiated_cipher_suite()
                            .map(|suite| format!("{:?}", suite.suite()))
                            .unwrap_or_else(|| "unknown".to_owned());
                        eprintln!("ACME HTTPS connection: peer={remote_addr}, version={version}, cipher_suite={cipher_suite}, key_exchange={key_exchange}");
                        let permit = match try_connection_slot(&connection_slots) {
                            Some(permit) => permit,
                            None => {
                                eprintln!("dropping HTTPS connection from {remote_addr}: active connection limit reached");
                                drop(tls_stream);
                                continue;
                            }
                        };
                        let client = client.clone();
                        let routes = Arc::clone(&routes);
                        tasks.spawn(async move {
                            let _connection_permit = permit;
                            serve_proxy_connection(Box::new(tls_stream), client, routes, remote_addr, "https").await;
                        });
                    }
                    Some(Err(error)) => eprintln!("ACME/TLS connection or renewal error: {error:?}"),
                    None => bail!("ACME incoming stream ended unexpectedly"),
                }
            }
            Some(completed) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = completed {
                    eprintln!("HTTP-01/HTTPS connection task failed: {error}");
                }
            }
        }
    }

    let draining = drain_connections(&mut tasks);
    if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, draining)
        .await
        .is_err()
    {
        let remaining = tasks.len();
        eprintln!("Grace period expired; aborting {remaining} remaining connection task(s).");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    } else {
        println!("Active connections drained cleanly.");
    }
    Ok(())
}

fn prepare_acme_cache(cache_dir: &Path) -> Result<()> {
    if !cache_dir.is_absolute() {
        bail!("ACME cache path must be absolute");
    }
    if let Ok(metadata) = std::fs::symlink_metadata(cache_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "ACME cache path must be a real directory, not a symlink or regular file: {}",
                cache_dir.display()
            );
        }
    }
    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "could not create ACME cache directory {}",
            cache_dir.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(cache_dir).with_context(|| {
        format!(
            "could not inspect ACME cache directory {}",
            cache_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "ACME cache path must be a real directory: {}",
            cache_dir.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "could not restrict ACME cache directory permissions at {}",
                    cache_dir.display()
                )
            },
        )?;
    }
    Ok(())
}

async fn serve_http01_connection(
    io_stream: BoxedStream,
    challenge_service: TowerHttp01ChallengeService,
    routes: Arc<Vec<Route>>,
    remote_addr: SocketAddr,
) {
    let service = service_fn(move |request: Request<Incoming>| {
        let challenge_service = challenge_service.clone();
        let routes = Arc::clone(&routes);
        async move {
            if request.uri().scheme().is_some() || request.uri().authority().is_some() {
                return Ok::<Response<ProxyBody>, Infallible>(response(
                    StatusCode::BAD_REQUEST,
                    "Absolute-form request targets are not supported.\n",
                ));
            }
            if request.headers().get_all(HOST).iter().count() != 1 {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "Exactly one Host header is required.\n",
                ));
            }
            let Some(host_value) = request.headers().get(HOST).cloned() else {
                return Ok(response(StatusCode::BAD_REQUEST, "Missing Host header.\n"));
            };
            let Some(hostname) = normalize_host(&host_value) else {
                return Ok(response(StatusCode::BAD_REQUEST, "Invalid Host header.\n"));
            };
            let Some(route) = routes
                .iter()
                .find(|route| route.domain.eq_ignore_ascii_case(&hostname))
            else {
                return Ok(response(
                    StatusCode::MISDIRECTED_REQUEST,
                    "No configured site matches this Host header.\n",
                ));
            };
            if request
                .uri()
                .path()
                .starts_with("/.well-known/acme-challenge/")
            {
                if request.method() != http::Method::GET {
                    return Ok(response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "HTTP-01 challenge requests must use GET.\n",
                    ));
                }
                let mut service = challenge_service;
                let challenge_response = match service.call(request).await {
                    Ok(response) => response,
                    Err(never) => match never {},
                };
                let (parts, body) = challenge_response.into_parts();
                let body = Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed_unsync();
                return Ok(Response::from_parts(parts, body));
            }
            let path_and_query = request
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let destination = format!("https://{}{}", route.domain, path_and_query);
            let Ok(location) = HeaderValue::from_str(&destination) else {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "Invalid redirect target.\n",
                ));
            };
            let mut redirect = response(StatusCode::PERMANENT_REDIRECT, "HTTPS is required.\n");
            redirect.headers_mut().insert(LOCATION, location);
            Ok(redirect)
        }
    });
    let mut server = http1::Builder::new();
    server
        .keep_alive(false)
        .max_headers(MAX_REQUEST_HEADER_COUNT)
        .max_header_size(MAX_REQUEST_HEADER_BYTES)
        .max_buf_size(MAX_REQUEST_HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(REQUEST_HEADER_TIMEOUT);
    if let Err(error) = server
        .serve_connection(TokioIo::new(io_stream), service)
        .await
    {
        eprintln!("HTTP-01/redirect connection error from {remote_addr}: {error}");
    }
}

pub(crate) fn validate_acme_email(email: &str) -> Result<()> {
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("--email must be a valid contact email address"))?;
    if local.is_empty()
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || email.len() > 254
        || !email.is_ascii()
        || email.chars().any(char::is_whitespace)
        || domain.split('.').count() < 2
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || email.matches('@').count() != 1
    {
        bail!("--email must be a valid contact email address");
    }
    Ok(())
}

pub(crate) fn validate_acme_domain(domain: &str) -> Result<()> {
    let canonical = domain.trim_end_matches('.').to_ascii_lowercase();
    let placeholder = canonical == "example.com"
        || canonical == "example.org"
        || canonical == "example.net"
        || canonical.split('.').any(|label| label == "example")
        || [".test", ".invalid", ".localhost", ".local"]
            .iter()
            .any(|suffix| canonical.ends_with(suffix));
    if placeholder {
        bail!("domain {domain} is a placeholder or reserved/local name; use a real public domain you control");
    }
    if !domain.contains('.')
        || domain.contains('*')
        || domain.contains('/')
        || domain.contains(':')
        || !domain.is_ascii()
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        bail!("invalid public DNS hostname for ACME: {domain}");
    }
    let labels: Vec<&str> = canonical.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        bail!("invalid DNS label in ACME hostname: {domain}");
    }
    Ok(())
}

async fn serve_proxy_connection(
    io_stream: BoxedStream,
    client: ProxyClient,
    routes: Arc<Vec<Route>>,
    remote_addr: SocketAddr,
    client_proto: &'static str,
) {
    let service = service_fn(move |request| {
        let client = client.clone();
        let routes = Arc::clone(&routes);
        async move {
            #[cfg(feature = "prometheus")]
            if request.uri().path() == "/.quantum-shield/metrics" {
                if !remote_addr.ip().is_loopback() {
                    return Ok::<Response<ProxyBody>, Infallible>(response(
                        StatusCode::NOT_FOUND,
                        "Not found.\n",
                    ));
                }
                let mut res = Response::new(
                    Full::new(Bytes::from(metrics::render()))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                );
                *res.status_mut() = StatusCode::OK;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );
                return Ok::<Response<ProxyBody>, Infallible>(res);
            }
            let response =
                handle_request(request, routes.as_ref(), &client, remote_addr, client_proto).await;
            #[cfg(feature = "prometheus")]
            metrics::observe(response.status().as_u16());
            Ok::<Response<ProxyBody>, Infallible>(response)
        }
    });
    let mut server = http1::Builder::new();
    server
        .keep_alive(false)
        .max_headers(MAX_REQUEST_HEADER_COUNT)
        .max_header_size(MAX_REQUEST_HEADER_BYTES)
        .max_buf_size(MAX_REQUEST_HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(REQUEST_HEADER_TIMEOUT);
    if let Err(error) = server
        .serve_connection(TokioIo::new(io_stream), service)
        .with_upgrades()
        .await
    {
        eprintln!(
            "local {} connection error: {error}",
            if client_proto == "https" {
                "HTTPS"
            } else {
                "HTTP"
            }
        );
    }
}

fn try_connection_slot(slots: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(slots).try_acquire_owned().ok()
}

async fn reject_over_capacity(mut stream: TcpStream) {
    // This is a tiny fixed response written before starting a Hyper task, so
    // overloaded clients cannot create an unbounded task queue.
    let _ = tokio::time::timeout(
        Duration::from_millis(250),
        stream.write_all(OVER_CAPACITY_REPLY),
    )
    .await;
    let _ = stream.shutdown().await;
}

async fn drain_connections(tasks: &mut JoinSet<()>) {
    while let Some(completed) = tasks.join_next().await {
        if let Err(error) = completed {
            eprintln!("connection task failed during shutdown: {error}");
        }
    }
}

const QS_GENERAL_REQUESTS_PER_MINUTE: u32 = 600;
const QS_AUTH_REQUESTS_PER_MINUTE: u32 = 10;
const QS_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const QS_MAX_RATE_LIMIT_ENTRIES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum QuantumShieldRateClass {
    General,
    Authentication,
}

#[derive(Clone, Copy, Debug)]
struct QuantumShieldRateWindow {
    started_at: std::time::Instant,
    count: u32,
}

fn quantum_shield_consume_rate_slot(
    windows: &mut std::collections::HashMap<
        (std::net::IpAddr, QuantumShieldRateClass),
        QuantumShieldRateWindow,
    >,
    ip: std::net::IpAddr,
    class: QuantumShieldRateClass,
    limit: u32,
    now: std::time::Instant,
) -> bool {
    let key = (ip, class);

    if let Some(window) = windows.get_mut(&key) {
        if now.saturating_duration_since(window.started_at) >= QS_RATE_WINDOW {
            window.started_at = now;
            window.count = 1;
            return true;
        }

        if window.count >= limit {
            return false;
        }

        window.count += 1;
        return true;
    }

    if windows.len() >= QS_MAX_RATE_LIMIT_ENTRIES {
        windows
            .retain(|_, window| now.saturating_duration_since(window.started_at) < QS_RATE_WINDOW);
    }

    // Bound memory under source-IP churn. Evict the oldest active window
    // so new legitimate clients are not globally denied service under churn.
    if windows.len() >= QS_MAX_RATE_LIMIT_ENTRIES {
        if let Some(oldest_key) = windows
            .iter()
            .min_by_key(|(_, window)| window.started_at)
            .map(|(k, _)| *k)
        {
            windows.remove(&oldest_key);
        }
    }

    windows.insert(
        key,
        QuantumShieldRateWindow {
            started_at: now,
            count: 1,
        },
    );
    true
}

fn quantum_shield_is_authentication_endpoint(path: &str) -> bool {
    let path = path.to_ascii_lowercase();

    path.ends_with("/login")
        || path.ends_with("/authenticate")
        || path.ends_with("/token")
        || path.contains("/password/reset")
        || path.contains("/reset-password")
        || path.contains("/forgot-password")
        || path.contains("/security-question")
}

fn quantum_shield_request_rate_limit(ip: std::net::IpAddr, path: &str) -> Option<StatusCode> {
    static WINDOWS: std::sync::OnceLock<
        std::sync::Mutex<
            std::collections::HashMap<
                (std::net::IpAddr, QuantumShieldRateClass),
                QuantumShieldRateWindow,
            >,
        >,
    > = std::sync::OnceLock::new();

    let windows = WINDOWS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    let mut windows = windows
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let now = std::time::Instant::now();

    if !quantum_shield_consume_rate_slot(
        &mut windows,
        ip,
        QuantumShieldRateClass::General,
        QS_GENERAL_REQUESTS_PER_MINUTE,
        now,
    ) {
        return Some(StatusCode::TOO_MANY_REQUESTS);
    }

    if quantum_shield_is_authentication_endpoint(path)
        && !quantum_shield_consume_rate_slot(
            &mut windows,
            ip,
            QuantumShieldRateClass::Authentication,
            QS_AUTH_REQUESTS_PER_MINUTE,
            now,
        )
    {
        return Some(StatusCode::TOO_MANY_REQUESTS);
    }

    None
}

#[cfg(feature = "circuit_breaker")]
fn upstream_circuit_breaker(name: &str) -> Arc<crate::circuit_breaker::CircuitBreaker> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static BREAKERS: OnceLock<Mutex<HashMap<String, Arc<crate::circuit_breaker::CircuitBreaker>>>> =
        OnceLock::new();
    let breakers = BREAKERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match breakers.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    Arc::clone(guard.entry(name.to_owned()).or_insert_with(|| {
        Arc::new(crate::circuit_breaker::CircuitBreaker::new(
            5,
            2,
            Duration::from_secs(15),
        ))
    }))
}

fn reject_uninspected_websocket(websocket_requested: bool) -> Option<Response<ProxyBody>> {
    if websocket_requested {
        Some(response(
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket upgrades are disabled because frame-level inspection is not implemented.\n",
        ))
    } else {
        None
    }
}

async fn handle_request(
    mut request: Request<Incoming>,
    routes: &[Route],
    client: &ProxyClient,
    remote_addr: SocketAddr,
    client_proto: &'static str,
) -> Response<ProxyBody> {
    // Apply peer-IP rate limits before WAF body buffering or upstream I/O.
    // Never trust client-supplied X-Forwarded-For for this decision.
    if let Some(status) = quantum_shield_request_rate_limit(remote_addr.ip(), request.uri().path())
    {
        eprintln!(
            "Request rate limit exceeded: client={} method={} path={} status={}",
            remote_addr.ip(),
            request.method(),
            request.uri().path(),
            status.as_u16()
        );
        return response(status, "Quantum Shield request rate limit exceeded.\n");
    }

    // An unsigned JWT must never be accepted as a bearer credential.
    // This does not replace application-specific signature, issuer, audience,
    // expiry, or authorization checks for signed tokens.
    if has_unsigned_jwt_credential(request.headers(), request.uri().query()) {
        eprintln!(
            "JWT policy blocked unsigned bearer token: method={} path={}",
            request.method(),
            request.uri().path()
        );
        return response(
            StatusCode::UNAUTHORIZED,
            "Unsigned bearer JWTs are not accepted by Quantum Shield.\n",
        );
    }

    if request.method() == http::Method::CONNECT {
        return response(
            StatusCode::NOT_IMPLEMENTED,
            "CONNECT is not supported by this reverse proxy prototype.\n",
        );
    }

    if request.method() == http::Method::TRACE {
        return response(StatusCode::METHOD_NOT_ALLOWED, "TRACE is disabled.\n");
    }

    if request.method().as_str() == "PURGE" {
        return response(StatusCode::FORBIDDEN, "PURGE method is not allowed.\n");
    }

    let requested_upgrade =
        request.headers().contains_key(UPGRADE) || connection_requests_upgrade(request.headers());
    let websocket_requested = request
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if let Some(rejection) = reject_uninspected_websocket(websocket_requested) {
        return rejection;
    }
    if requested_upgrade {
        return response(
            StatusCode::NOT_IMPLEMENTED,
            "This protocol upgrade is not supported.\n",
        );
    }
    let websocket_upgrade = false;

    let mut downstream_upgrade = if websocket_upgrade {
        Some(hyper::upgrade::on(&mut request))
    } else {
        None
    };

    let mut websocket_permit = if websocket_upgrade {
        match websocket_tunnel_semaphore().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "WebSocket tunnel capacity reached.\n",
                );
            }
        }
    } else {
        None
    };

    // Reject obviously oversized fixed-length requests before opening an upstream
    // request. Streaming/chunked body enforcement is a separate follow-up gate.
    if let Err(status) = validate_declared_content_length(request.headers()) {
        let message = if status == StatusCode::PAYLOAD_TOO_LARGE {
            "Declared request body exceeds the prototype limit.\n"
        } else {
            "Invalid or duplicate Content-Length header.\n"
        };
        return response(status, message);
    }

    // This server is a reverse proxy, not a forward proxy. Only origin-form
    // request targets are accepted, avoiding ambiguous authority routing.
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return response(
            StatusCode::BAD_REQUEST,
            "Absolute-form request targets are not supported.\n",
        );
    }

    if request.headers().get_all(HOST).iter().count() > 1 {
        return response(
            StatusCode::BAD_REQUEST,
            "Multiple Host headers are not supported.\n",
        );
    }
    let Some(host_value) = request.headers().get(HOST).cloned() else {
        return response(StatusCode::BAD_REQUEST, "Missing Host header.\n");
    };
    let Some(hostname) = normalize_host(&host_value) else {
        return response(StatusCode::BAD_REQUEST, "Invalid Host header.\n");
    };
    let Some(route) = routes
        .iter()
        .find(|route| route.domain.eq_ignore_ascii_case(&hostname))
    else {
        return response(
            StatusCode::MISDIRECTED_REQUEST,
            "No configured site matches this Host header.\n",
        );
    };
    // Optional operator-configured crawler policy. This is an access-control
    // rule, not proof of crawler identity; User-Agent headers can be spoofed.
    if user_agent_matches_blocklist(
        request.headers().get(USER_AGENT),
        configured_blocked_user_agents(),
    ) {
        let mut res = response(
            StatusCode::FORBIDDEN,
            "Request blocked by configured User-Agent policy.\n",
        );
        res.headers_mut().insert(
            HeaderName::from_static("x-quantum-shield-policy"),
            HeaderValue::from_static("ai-agent-blocked"),
        );
        return res;
    }

    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    // Preserve the original request path for WAF path-traversal inspection.
    // The request URI is rewritten to the upstream destination below,
    // so we keep a copy here so the WAF can see the client-supplied path.
    let original_path_and_query = Some(path_and_query.to_owned());
    let path_and_query = if path_and_query == "*" {
        "/"
    } else {
        path_and_query
    };
    let target_uri = match format!("{}{}", route.upstream, path_and_query).parse::<Uri>() {
        Ok(uri) if uri.scheme_str() == Some("http") && uri.authority().is_some() => uri,
        _ => {
            return response(
                StatusCode::BAD_GATEWAY,
                "Configured upstream URL could not be constructed.\n",
            )
        }
    };
    let Some(upstream_authority) = target_uri.authority() else {
        return response(
            StatusCode::BAD_GATEWAY,
            "Configured upstream has no authority.\n",
        );
    };
    let Ok(upstream_host_header) = HeaderValue::from_str(upstream_authority.as_str()) else {
        return response(
            StatusCode::BAD_GATEWAY,
            "Configured upstream authority is invalid.\n",
        );
    };

    *request.uri_mut() = target_uri;
    strip_hop_by_hop(request.headers_mut());
    if websocket_upgrade {
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        request
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    }

    // Never trust a client-supplied forwarding chain at this listener. We are
    // the only proxy hop in this prototype, so overwrite the forwarding fields.
    for name in [
        "forwarded",
        "x-forwarded-client-cert",
        "x-forwarded-server",
        "x-forwarded-port",
        "x-original-url",
        "x-rewrite-url",
    ] {
        request.headers_mut().remove(name);
    }
    request.headers_mut().insert(HOST, upstream_host_header);
    request.headers_mut().insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&remote_addr.ip().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    request.headers_mut().insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(client_proto),
    );
    request.headers_mut().insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_str(&remote_addr.ip().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    request
        .headers_mut()
        .insert(HeaderName::from_static("x-forwarded-host"), host_value);

    // Inspect complete bounded bodies before opening the upstream request.
    // Never forward a request if WAF initialization or evaluation fails.
    let body_may_be_present =
        !(request.body().is_end_stream() || request.body().size_hint().exact() == Some(0));

    let waf_body_slot = if body_may_be_present {
        match tokio::time::timeout(Duration::from_secs(5), waf_body_buffer_slots().acquire()).await
        {
            Ok(Ok(permit)) => Some(permit),
            _ => {
                return response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Quantum Shield request inspection capacity is full.\n",
                );
            }
        }
    } else {
        None
    };

    let (waf_parts, incoming_body) = request.into_parts();
    let inspected_body = match collect_waf_body(incoming_body).await {
        Ok(body) => body,
        Err(WafBodyReadError::TooLarge) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body exceeds the 16 MiB limit.\n",
            );
        }
        Err(WafBodyReadError::IdleTimeout | WafBodyReadError::TotalTimeout) => {
            return response(
                StatusCode::REQUEST_TIMEOUT,
                "Client request body timed out during security inspection.\n",
            );
        }
        Err(WafBodyReadError::Invalid) => {
            return response(
                StatusCode::BAD_REQUEST,
                "Invalid request body during security inspection.\n",
            );
        }
    };

    // Optional payload gate: inspect only supported textual body types and fail closed
    // for malformed JSON, invalid-UTF-8 form bodies, or bodies over the inspection cap. This does not replace
    // the live ModSecurity CRS inspection below and is disabled unless --features body_gate.
    #[cfg(feature = "body_gate")]
    {
        let content_type = waf_parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let body_class = crate::body_gate::classify_content_type(content_type);
        if crate::body_gate::inspect_buffered_body(body_class, &inspected_body)
            == crate::body_gate::BodyDecision::Reject
        {
            return response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Request payload rejected by Quantum Shield body gate.\n",
            );
        }
    }

    // Use the original request path for WAF inspection, captured before the
    // request URI was rewritten to the upstream destination. This ensures
    // path-traversal signatures (../, %2e%2e%2f, etc.) are detected against
    // the client-supplied path rather than the rewritten upstream URL.
    let waf_uri = original_path_and_query.as_deref().unwrap_or("/");

    match inspect_waf_request(
        waf_parts.method.as_str(),
        waf_uri,
        &waf_parts.headers,
        &inspected_body,
    ) {
        Ok(Some((raw_status, rule_id))) => {
            let status = StatusCode::from_u16(raw_status).unwrap_or(StatusCode::FORBIDDEN);
            // Never log query strings, headers, or body contents.
            eprintln!(
                "WAF blocked request: method={} path={} status={} rule={}",
                waf_parts.method,
                waf_parts.uri.path(),
                status.as_u16(),
                rule_id
            );
            return response(status, "Request blocked by Quantum Shield WAF.\n");
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("WAF inspection failed; request rejected: {error}");
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Quantum Shield security inspection is unavailable.\n",
            );
        }
    }

    // Free the WAF body buffering slot immediately once inspection completes.
    drop(waf_body_slot);

    // Rebuild the request only after its body has passed WAF inspection.
    // The bounded upstream body pump below remains responsible for forwarding.
    let request = Request::from_parts(waf_parts, http_body_util::Full::new(inspected_body));

    // Determine whether Hyper already knows this request body is empty. Giving
    // the outbound body an exact-zero size hint prevents needless chunked-body
    // framing on ordinary GET/HEAD requests and avoids racing an early upstream
    // response against an artificial empty stream.
    let request_expected_content_length = declared_content_length(request.headers()).ok().flatten();

    let request_body_known_empty =
        request.body().is_end_stream() || request.body().size_hint().exact() == Some(0);

    // Optional per-host circuit breaker. Default builds preserve existing behavior.
    #[cfg(feature = "circuit_breaker")]
    let upstream_breaker = upstream_circuit_breaker(&route.domain);
    #[cfg(feature = "circuit_breaker")]
    if !upstream_breaker.check_access() {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configured upstream is temporarily unavailable (circuit open).\n",
        );
    }

    // Pump the client upload independently from the upstream response. This
    // prevents an upstream's early 200 response from bypassing body limits.
    let (body_sender, body_receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
    let body_end_polled = Arc::new(AtomicBool::new(request_body_known_empty));
    let (request_parts, incoming_body) = request.into_parts();
    let outbound_body = PumpedBody {
        receiver: body_receiver,
        end_polled: Arc::clone(&body_end_polled),
        known_empty: request_body_known_empty,
        expected_content_length: request_expected_content_length,
        forwarded_bytes: 0,
    };
    let outbound_request = Request::from_parts(request_parts, outbound_body);

    let mut body_task = tokio::spawn(async move {
        match tokio::time::timeout(
            REQUEST_BODY_TOTAL_TIMEOUT,
            pump_request_body(incoming_body, body_sender, MAX_REQUEST_BODY_BYTES),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => RequestBodyOutcome::TotalTimeout,
        }
    });

    let mut upstream_future = Box::pin(tokio::time::timeout(
        UPSTREAM_REQUEST_TIMEOUT,
        client.request(outbound_request),
    ));
    let mut upstream_result = None;
    let mut body_outcome: Option<RequestBodyOutcome> = None;

    loop {
        if let Some(outcome) = body_outcome {
            let terminal_response = match outcome {
                RequestBodyOutcome::Complete | RequestBodyOutcome::CompleteEmpty => None,
                RequestBodyOutcome::TooLarge => Some((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body exceeds the 16 MiB limit.\n",
                )),
                RequestBodyOutcome::InvalidBody => Some((
                    StatusCode::BAD_REQUEST,
                    "Could not read the complete client request body.\n",
                )),
                RequestBodyOutcome::IdleTimeout | RequestBodyOutcome::TotalTimeout => Some((
                    StatusCode::REQUEST_TIMEOUT,
                    "Client request body timed out.\n",
                )),
            };
            if let Some((status, message)) = terminal_response {
                return response(status, message);
            }
        }

        if upstream_result.is_some() && body_outcome.is_some() {
            break;
        }

        tokio::select! {
            result = &mut upstream_future, if upstream_result.is_none() => {
                upstream_result = Some(result);
            }
            result = &mut body_task, if body_outcome.is_none() => {
                body_outcome = Some(match result {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        eprintln!("request-body pump task failed: {error}");
                        return response(StatusCode::BAD_GATEWAY, "Request-body processing failed.\n");
                    }
                });
            }
        }
    }

    let mut upstream_response =
        match upstream_result.expect("loop exits only after upstream result") {
            Err(_) => {
                #[cfg(feature = "circuit_breaker")]
                upstream_breaker.record_failure();
                return response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Timed out waiting for the upstream response.\n",
                );
            }
            Ok(Err(error)) => {
                #[cfg(feature = "circuit_breaker")]
                upstream_breaker.record_failure();
                eprintln!("upstream request failed: {error}");
                return response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream connection or request-body forwarding failed.\n",
                );
            }
            Ok(Ok(upstream_response)) => {
                // If the incoming request had no body frames, it is safe to relay
                // the response even if Hyper did not poll the synthetic outbound
                // body's EOF marker before the upstream replied. This is common for
                // ordinary GET/HEAD requests. For any request that supplied frames,
                // still require the outbound body stream to have been fully consumed;
                // otherwise an upstream early response could bypass body validation.
                let inbound_outcome = body_outcome.expect("loop exits only after body outcome");
                if !can_relay_upstream_response(
                    inbound_outcome,
                    body_end_polled.load(Ordering::Acquire),
                ) {
                    #[cfg(feature = "circuit_breaker")]
                    upstream_breaker.record_failure();
                    return response(
                        StatusCode::BAD_GATEWAY,
                        "Upstream stopped consuming the request before it was complete.\n",
                    );
                }
                #[cfg(feature = "circuit_breaker")]
                if upstream_response.status().is_server_error() {
                    upstream_breaker.record_failure();
                } else {
                    upstream_breaker.record_success();
                }
                upstream_response
            }
        };

    if websocket_upgrade && upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let headers = upstream_response.headers();

        // Refuse malformed upstream upgrades. The browser still validates the
        // Sec-WebSocket-Accept value against its original key.
        let upstream_websocket = headers
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
            && connection_requests_upgrade(headers)
            && headers.contains_key("sec-websocket-accept");

        if !upstream_websocket {
            return response(
                StatusCode::BAD_GATEWAY,
                "Malformed upstream WebSocket handshake.\n",
            );
        }

        let Some(downstream_upgrade) = downstream_upgrade.take() else {
            return response(StatusCode::BAD_GATEWAY, "Downstream upgrade unavailable.\n");
        };
        let Some(permit) = websocket_permit.take() else {
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                "WebSocket tunnel capacity unavailable.\n",
            );
        };

        let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
        let mut response_headers = upstream_response.headers().clone();
        strip_hop_by_hop(&mut response_headers);
        response_headers.remove(CONTENT_LENGTH);
        response_headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        response_headers.insert(UPGRADE, HeaderValue::from_static("websocket"));

        tokio::spawn(async move {
            let downstream = match downstream_upgrade.await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("downstream WebSocket upgrade failed: {error}");
                    drop(permit);
                    return;
                }
            };
            let upstream = match upstream_upgrade.await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("upstream WebSocket upgrade failed: {error}");
                    drop(permit);
                    return;
                }
            };

            let mut downstream = TokioIo::new(downstream);
            let mut upstream = TokioIo::new(upstream);
            if let Err(error) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
            {
                eprintln!("WebSocket tunnel ended: {error}");
            }
            drop(permit);
        });

        let mut switching = response(StatusCode::SWITCHING_PROTOCOLS, "");
        *switching.headers_mut() = response_headers;
        return switching;
    }

    let mut upstream_response = upstream_response.map(|body| body.boxed_unsync());
    strip_hop_by_hop(upstream_response.headers_mut());
    #[cfg(feature = "dlp")]
    let upstream_response = dlp_filter_response(upstream_response).await;
    upstream_response
}

/// Apply textual DLP redaction to buffered text responses. Binary, compressed,
/// and signed payloads are never rewritten: DLP fails closed on text responses
/// it cannot inspect safely rather than forwarding unscanned content.
#[cfg(feature = "dlp")]
async fn dlp_filter_response(mut upstream: Response<ProxyBody>) -> Response<ProxyBody> {
    use bytes::BytesMut;
    use http::header::CONTENT_ENCODING;

    const MAX_DLP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

    let Some(content_type) = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
    else {
        return upstream;
    };
    let textual = content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("javascript")
        || content_type.contains("xml");
    if !textual {
        return upstream;
    }

    let content_encoding = upstream
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if upstream
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_DLP_RESPONSE_BYTES)
    {
        return crate::proxy::response(
            StatusCode::BAD_GATEWAY,
            "Response blocked: text payload exceeds the DLP inspection limit.\n",
        );
    }

    let mut collected = Vec::new();
    loop {
        match upstream.body_mut().frame().await {
            None => break,
            Some(Err(_)) => {
                return crate::proxy::response(
                    StatusCode::BAD_GATEWAY,
                    "Response blocked: DLP could not read the upstream body.\n",
                )
            }
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if collected.len().saturating_add(data.len()) > MAX_DLP_RESPONSE_BYTES {
                        return crate::proxy::response(
                            StatusCode::BAD_GATEWAY,
                            "Response blocked: text payload exceeds the DLP inspection limit.\n",
                        );
                    }
                    collected.extend_from_slice(data);
                }
            }
        }
    }

    let inspected = match content_encoding.as_deref() {
        Some(header) => match crate::dlp::decode_content_encoded(&collected, header) {
            Ok(decoded) => decoded,
            Err(_) => {
                return crate::proxy::response(
                    StatusCode::BAD_GATEWAY,
                    "Response blocked: DLP cannot decode the response content encoding.\n",
                )
            }
        },
        None => BytesMut::from(&collected[..]),
    };
    let transformed = crate::dlp::transform_body(inspected);
    let bytes = Bytes::from(transformed.to_vec());
    upstream.headers_mut().remove(CONTENT_ENCODING);
    upstream.headers_mut().remove(CONTENT_LENGTH);
    if let Ok(length) = HeaderValue::from_str(&bytes.len().to_string()) {
        upstream.headers_mut().insert(CONTENT_LENGTH, length);
    }
    *upstream.body_mut() = Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync();
    upstream
}

/// Decide whether it is safe to relay an upstream response after the body
/// pump completed. Requests without any body frames are safe even when the
/// upstream never polls the synthetic empty-body EOF marker. If any frame was
/// present, the proxy requires confirmation that the outbound stream reached EOF.
fn can_relay_upstream_response(outcome: RequestBodyOutcome, outbound_end_polled: bool) -> bool {
    match outcome {
        RequestBodyOutcome::CompleteEmpty => true,
        RequestBodyOutcome::Complete => outbound_end_polled,
        RequestBodyOutcome::TooLarge
        | RequestBodyOutcome::InvalidBody
        | RequestBodyOutcome::IdleTimeout
        | RequestBodyOutcome::TotalTimeout => false,
    }
}

pub(crate) const QUANTUM_SHIELD_WAF_RULES: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@detectSQLi" "id:100001,phase:2,deny,status:403,msg:'Quantum Shield SQL injection detection'"
SecRule ARGS "@detectXSS" "id:100002,phase:2,deny,status:403,msg:'Quantum Shield XSS detection'"
SecRule REQUEST_BODY "@detectSQLi" "id:100003,phase:2,deny,status:403,msg:'Quantum Shield request-body SQL injection detection'"
SecRule REQUEST_BODY "@detectXSS" "id:100004,phase:2,deny,status:403,msg:'Quantum Shield request-body XSS detection'"
SecRule REQUEST_URI "@rx (?i)(?:\\.\\./|%2e%2e%2f|%252e%252e)" "id:100005,phase:1,deny,status:403,msg:'Quantum Shield path traversal detection'"
SecRule REQUEST_URI "@rx (?i)(?:^|/)(?:\\.env(?:[/?]|$)|\\.git(?:/|$)|wp-config\\.php(?:[/?]|$))" "id:100006,phase:1,deny,status:403,msg:'Quantum Shield sensitive file path detection'"
SecRule REQUEST_METHOD "@streq TRACE" "id:100007,phase:1,deny,status:403,msg:'Quantum Shield TRACE method disabled'"
SecRule ARGS "@rx (?i)(?:\\$\\([^)]{1,80}\\)|`[^`]{1,80}`)" "id:100008,phase:2,deny,status:403,msg:'Quantum Shield shell substitution detection'"
SecRule REQUEST_BODY "@rx (?i)(?:\\$\\([^)]{1,80}\\)|`[^`]{1,80}`)" "id:100009,phase:2,deny,status:403,msg:'Quantum Shield request-body shell substitution detection'"
"#;

fn build_quantum_shield_waf(
    config_path: Option<&str>,
) -> std::result::Result<zentinel_modsec::ModSecurity, String> {
    match config_path {
        Some(path) if path.trim().is_empty() => {
            Err("QUANTUM_SHIELD_WAF_CONFIG must not be empty".to_owned())
        }
        Some(path) => zentinel_modsec::ModSecurity::from_file(path)
            .map_err(|error| format!("failed to load configured WAF rules from {path}: {error}")),
        None => zentinel_modsec::ModSecurity::from_string(QUANTUM_SHIELD_WAF_RULES)
            .map_err(|error| format!("failed to load built-in Quantum Shield WAF rules: {error}")),
    }
}

fn quantum_shield_waf() -> std::result::Result<&'static zentinel_modsec::ModSecurity, String> {
    static ENGINE: std::sync::OnceLock<std::result::Result<zentinel_modsec::ModSecurity, String>> =
        std::sync::OnceLock::new();

    ENGINE
        .get_or_init(|| {
            let configured_path = match std::env::var("QUANTUM_SHIELD_WAF_CONFIG") {
                Ok(path) => Some(path),
                Err(std::env::VarError::NotPresent) => None,
                Err(error) => {
                    return Err(format!("could not read QUANTUM_SHIELD_WAF_CONFIG: {error}"));
                }
            };

            build_quantum_shield_waf(configured_path.as_deref())
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn inspect_waf_request(
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> std::result::Result<Option<(u16, String)>, String> {
    let engine = quantum_shield_waf()?;
    let mut transaction = engine.new_transaction();

    transaction
        .process_uri(uri, method, "HTTP/1.1")
        .map_err(|error| format!("WAF URI processing failed: {error}"))?;

    for (name, value) in headers {
        let value = value
            .to_str()
            .map_err(|_| "WAF could not inspect a non-text request header".to_string())?;

        transaction
            .add_request_header(name.as_str(), value)
            .map_err(|error| format!("WAF header processing failed: {error}"))?;
    }

    transaction
        .process_request_headers()
        .map_err(|error| format!("WAF header phase failed: {error}"))?;

    if let Some(intervention) = transaction.intervention() {
        return Ok(Some((
            intervention.status,
            format!("{:?}", intervention.rule_ids),
        )));
    }

    transaction
        .append_request_body(body)
        .map_err(|error| format!("WAF body processing failed: {error}"))?;

    transaction
        .process_request_body()
        .map_err(|error| format!("WAF body phase failed: {error}"))?;

    Ok(transaction
        .intervention()
        .map(|intervention| (intervention.status, format!("{:?}", intervention.rule_ids))))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WafBodyReadError {
    TooLarge,
    IdleTimeout,
    TotalTimeout,
    Invalid,
}

fn waf_body_buffer_slots() -> &'static tokio::sync::Semaphore {
    // At most eight request bodies can be buffered for inspection at once.
    // This bounds the WAF's additional body memory to roughly 128 MiB at
    // the existing 16 MiB per-request cap.
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(8))
}

async fn collect_waf_body<B>(mut incoming: B) -> Result<Bytes, WafBodyReadError>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Display + Send + 'static,
{
    let started = std::time::Instant::now();
    let mut collected = Vec::<u8>::new();

    loop {
        let total_remaining = REQUEST_BODY_TOTAL_TIMEOUT.saturating_sub(started.elapsed());

        if total_remaining.is_zero() {
            return Err(WafBodyReadError::TotalTimeout);
        }

        let wait = REQUEST_BODY_IDLE_TIMEOUT.min(total_remaining);
        let total_timeout_is_next = wait == total_remaining;

        match tokio::time::timeout(wait, incoming.frame()).await {
            Err(_) if total_timeout_is_next => {
                return Err(WafBodyReadError::TotalTimeout);
            }
            Err(_) => return Err(WafBodyReadError::IdleTimeout),
            Ok(None) => return Ok(Bytes::from(collected)),
            Ok(Some(Err(_))) => return Err(WafBodyReadError::Invalid),
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let Some(next_len) = collected.len().checked_add(data.len()) else {
                        return Err(WafBodyReadError::TooLarge);
                    };

                    if next_len > MAX_REQUEST_BODY_BYTES {
                        return Err(WafBodyReadError::TooLarge);
                    }

                    collected.extend_from_slice(data);
                }
            }
        }
    }
}

fn token_uses_unsigned_jwt_algorithm(token: &str) -> bool {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    let mut parts = token.split('.');
    let Some(header_segment) = parts.next() else {
        return false;
    };
    if parts.next().is_none() {
        return false;
    }
    let Some(_signature_segment) = parts.next() else {
        return false;
    };

    // Reject the unsecured "none" algorithm even if a client adds a
    // non-empty signature segment. It must never be treated as authenticated.
    if parts.next().is_some() {
        return false;
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(header_segment)
        .or_else(|_| URL_SAFE.decode(header_segment));

    let Ok(bytes) = decoded else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };

    header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|alg| alg.eq_ignore_ascii_case("none"))
}

fn has_unsigned_jwt_credential(headers: &HeaderMap, query: Option<&str>) -> bool {
    if has_unsigned_bearer_jwt(headers) {
        return true;
    }

    // Common application cookie names for JWT credentials.
    for cookie_header in headers.get_all("cookie").iter() {
        let Ok(raw) = cookie_header.to_str() else {
            continue;
        };

        for cookie in raw.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };

            if matches!(
                name.trim().to_ascii_lowercase().as_str(),
                "token" | "jwt" | "access_token"
            ) && token_uses_unsigned_jwt_algorithm(value.trim())
            {
                return true;
            }
        }
    }

    // Query-string credentials are discouraged, but if an application uses
    // them, reject an unsecured JWT rather than forwarding it upstream.
    if let Some(query) = query {
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "token" | "jwt" | "access_token"
            ) && token_uses_unsigned_jwt_algorithm(value.as_ref())
            {
                return true;
            }
        }
    }

    false
}

fn has_unsigned_bearer_jwt(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };

    scheme.eq_ignore_ascii_case("bearer") && token_uses_unsigned_jwt_algorithm(token.trim())
}

fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let raw = value.to_str().map_err(|_| ())?;
    let parsed = raw.parse::<u64>().map_err(|_| ())?;
    Ok(Some(parsed))
}

fn validate_declared_content_length(headers: &HeaderMap) -> Result<(), StatusCode> {
    match declared_content_length(headers) {
        Ok(Some(length)) if length > MAX_REQUEST_BODY_BYTES as u64 => {
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        }
        Err(()) => Err(StatusCode::BAD_REQUEST),
        _ => Ok(()),
    }
}

const BUILTIN_AI_AGENT_PATTERNS: &[&str] = &[
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "openai",
    "claudebot",
    "claude-user",
    "claude-searchbot",
    "anthropic",
    "perplexitybot",
    "perplexity-user",
    "google-extended",
    "googleother",
    "gemini",
    "ccbot",
    "bytespider",
    "amazonbot",
    "applebot-extended",
    "meta-externalagent",
    "meta-externalfetcher",
    "facebookbot",
    "cohere",
    "diffbot",
    "youbot",
    "timpibot",
    "omgilibot",
    "webz.io",
    "ai2bot",
    "imagesiftbot",
    "copilot",
    "langchain",
    "autogpt",
    "crewai",
    "cursor",
    "artex",
    "nuclei",
    "sqlmap",
    "nikto",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "dirbuster",
    "wfuzz",
    "masscan",
    "nmap",
    "acunetix",
    "nessus",
    "openvas",
    "w3af",
    "owasp zap",
    "headlesschrome",
    "playwright",
    "puppeteer",
    "selenium",
    "webdriver",
    "phantomjs",
];

fn configured_blocked_user_agents() -> &'static [String] {
    static BLOCKED: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

    BLOCKED.get_or_init(|| {
        let mut patterns = BUILTIN_AI_AGENT_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        if let Ok(extra) = std::env::var("QS_BLOCKED_USER_AGENTS") {
            for entry in extra.split(',').map(str::trim) {
                if !entry.is_empty() && entry.len() <= 128 {
                    let canonical = entry.to_ascii_lowercase();
                    if !patterns.contains(&canonical) {
                        patterns.push(canonical);
                    }
                }
            }
        }

        patterns
    })
}

fn user_agent_matches_blocklist(user_agent: Option<&HeaderValue>, patterns: &[String]) -> bool {
    let Some(user_agent) = user_agent.and_then(|value| value.to_str().ok()) else {
        return false;
    };

    let user_agent = user_agent.to_ascii_lowercase();

    patterns
        .iter()
        .any(|pattern| !pattern.is_empty() && user_agent.contains(pattern))
}

fn normalize_host(value: &HeaderValue) -> Option<String> {
    let raw = value.to_str().ok()?;
    let authority = raw.parse::<Authority>().ok()?;
    let hostname = authority.host().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

#[cfg(test)]
fn valid_websocket_handshake(
    method: &http::Method,
    version: http::Version,
    headers: &HeaderMap,
) -> bool {
    let one_key = headers.get_all("sec-websocket-key").iter().count() == 1;
    let key_ok = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|key| {
            let bytes = key.as_bytes();
            bytes.len() == 24
                && bytes.ends_with(b"==")
                && bytes[..22]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'/'))
        });

    let one_version = headers.get_all("sec-websocket-version").iter().count() == 1;
    let version_ok = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        == Some("13");

    let content_length_ok = headers.get_all(CONTENT_LENGTH).iter().count() <= 1
        && headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|value| value == "0");

    *method == http::Method::GET
        && version == http::Version::HTTP_11
        && headers
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && connection_requests_upgrade(headers)
        && one_key
        && key_ok
        && one_version
        && version_ok
        && content_length_ok
        && !headers.contains_key("transfer-encoding")
}

fn websocket_tunnel_semaphore() -> Arc<Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    Arc::clone(SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS))))
}

fn connection_requests_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// Remove standard hop-by-hop headers and every header named by Connection.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated_headers: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in nominated_headers {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    let mut result = Response::new(full_body(message));
    *result.status_mut() = status;
    result.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    result
}

fn full_body(message: &'static str) -> ProxyBody {
    Full::new(Bytes::from_static(message.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChunkBody {
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl ChunkBody {
        fn from_static_chunks(chunks: &[&'static [u8]]) -> Self {
            Self {
                chunks: chunks
                    .iter()
                    .map(|chunk| Bytes::from_static(chunk))
                    .collect(),
            }
        }
    }

    impl HttpBody for ChunkBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(
                self.get_mut()
                    .chunks
                    .pop_front()
                    .map(|chunk| Ok(Frame::data(chunk))),
            )
        }
    }

    #[tokio::test]
    async fn fixed_length_body_marks_complete_without_polling_eof() {
        let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        sender
            .send(Ok(Frame::data(Bytes::from_static(b"data"))))
            .await
            .expect("test body receiver should be available");

        let end_polled = Arc::new(AtomicBool::new(false));
        let mut body = PumpedBody {
            receiver,
            end_polled: Arc::clone(&end_polled),
            known_empty: false,
            expected_content_length: Some(4),
            forwarded_bytes: 0,
        };

        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(matches!(frame, Some(Ok(_))));
        assert!(
            end_polled.load(Ordering::Acquire),
            "the declared Content-Length should be complete without an EOF poll"
        );
    }

    #[test]
    fn pumped_body_requires_terminal_poll_to_record_eof() {
        let (sender, receiver) = mpsc::channel(1);
        drop(sender);
        let end_polled = Arc::new(AtomicBool::new(false));
        let body = PumpedBody {
            receiver,
            end_polled: Arc::clone(&end_polled),
            known_empty: false,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        assert!(!body.is_end_stream());
        assert!(!end_polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn known_empty_outbound_body_has_exact_zero_size_hint() {
        let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        drop(sender);
        let end_polled = Arc::new(AtomicBool::new(true));
        let body = PumpedBody {
            receiver,
            end_polled: Arc::clone(&end_polled),
            known_empty: true,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        let collected = body
            .collect()
            .await
            .expect("empty body should collect")
            .to_bytes();
        assert!(collected.is_empty());
        assert!(end_polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn body_with_no_frames_is_classified_as_complete_empty() {
        let (sender, _receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let outcome = pump_request_body(ChunkBody::from_static_chunks(&[]), sender, 4).await;
        assert_eq!(outcome, RequestBodyOutcome::CompleteEmpty);
    }

    #[test]
    fn early_upstream_response_is_allowed_for_bodyless_request() {
        assert!(can_relay_upstream_response(
            RequestBodyOutcome::CompleteEmpty,
            false
        ));
    }

    #[test]
    fn early_upstream_response_is_rejected_when_request_frames_were_not_consumed() {
        assert!(!can_relay_upstream_response(
            RequestBodyOutcome::Complete,
            false
        ));
        assert!(can_relay_upstream_response(
            RequestBodyOutcome::Complete,
            true
        ));
    }

    #[tokio::test]
    async fn streaming_body_limit_accepts_exact_limit_across_multiple_frames() {
        let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let end_polled = Arc::new(AtomicBool::new(false));
        let pump = tokio::spawn(async move {
            pump_request_body(ChunkBody::from_static_chunks(&[b"ab", b"cd"]), sender, 4).await
        });
        let body = PumpedBody {
            receiver,
            end_polled: Arc::clone(&end_polled),
            known_empty: false,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        let bytes = body
            .collect()
            .await
            .expect("body at limit should pass")
            .to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"abcd"));
        assert_eq!(
            pump.await.expect("body pump task should finish"),
            RequestBodyOutcome::Complete
        );
        assert!(end_polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn streaming_body_limit_rejects_cumulative_overflow() {
        let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let pump = tokio::spawn(async move {
            pump_request_body(
                ChunkBody::from_static_chunks(&[b"ab", b"cd", b"e"]),
                sender,
                4,
            )
            .await
        });
        let body = PumpedBody {
            receiver,
            end_polled: Arc::new(AtomicBool::new(false)),
            known_empty: false,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        assert!(
            body.collect().await.is_err(),
            "over-limit stream should signal an error"
        );
        assert_eq!(
            pump.await.expect("body pump task should finish"),
            RequestBodyOutcome::TooLarge
        );
    }

    #[tokio::test]
    async fn streaming_body_limit_rejects_a_single_oversized_frame() {
        let (sender, receiver) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let pump = tokio::spawn(async move {
            pump_request_body(ChunkBody::from_static_chunks(&[b"12345"]), sender, 4).await
        });
        let body = PumpedBody {
            receiver,
            end_polled: Arc::new(AtomicBool::new(false)),
            known_empty: false,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        assert!(body.collect().await.is_err());
        assert_eq!(
            pump.await.expect("body pump task should finish"),
            RequestBodyOutcome::TooLarge
        );
    }

    #[tokio::test]
    async fn body_pump_detects_oversize_even_after_upstream_drops_receiver() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let outcome = pump_request_body(
            ChunkBody::from_static_chunks(&[b"ab", b"cd", b"e"]),
            sender,
            4,
        )
        .await;
        assert_eq!(outcome, RequestBodyOutcome::TooLarge);
    }

    #[tokio::test]
    async fn dropped_upstream_body_receiver_does_not_mark_body_as_fully_forwarded() {
        let (sender, receiver) = mpsc::channel(1);
        let end_polled = Arc::new(AtomicBool::new(false));
        let body = PumpedBody {
            receiver,
            end_polled: Arc::clone(&end_polled),
            known_empty: false,
            expected_content_length: None,
            forwarded_bytes: 0,
        };
        drop(body);
        let outcome =
            pump_request_body(ChunkBody::from_static_chunks(&[b"ab", b"cd"]), sender, 4).await;
        assert_eq!(outcome, RequestBodyOutcome::Complete);
        assert!(!end_polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn refuses_non_loopback_bind_before_opening_listener() {
        let config = Config {
            schema_version: crate::config::SUPPORTED_SCHEMA_VERSION,
            sites: Vec::new(),
        };
        let address: SocketAddr = "0.0.0.0:8081"
            .parse()
            .expect("valid socket address literal");
        assert!(serve_http(config, address).await.is_err());
    }

    #[test]
    fn active_connection_semaphore_enforces_limit() {
        let slots = Arc::new(Semaphore::new(2));
        let first = try_connection_slot(&slots).expect("first slot available");
        let second = try_connection_slot(&slots).expect("second slot available");
        assert!(try_connection_slot(&slots).is_none());
        drop(first);
        assert!(try_connection_slot(&slots).is_some());
        drop(second);
    }

    #[test]
    fn declared_content_length_is_parsed_and_duplicates_rejected() {
        let mut headers = HeaderMap::new();
        assert_eq!(declared_content_length(&headers), Ok(None));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1024"));
        assert_eq!(declared_content_length(&headers), Ok(Some(1024)));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("1024"));
        assert!(declared_content_length(&headers).is_err());
    }

    #[test]
    fn declared_body_limit_rejects_oversize_and_accepts_boundary() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&MAX_REQUEST_BODY_BYTES.to_string()).unwrap(),
        );
        assert_eq!(validate_declared_content_length(&headers), Ok(()));
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&(MAX_REQUEST_BODY_BYTES as u64 + 1).to_string()).unwrap(),
        );
        assert_eq!(
            validate_declared_content_length(&headers),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[test]
    fn duplicate_content_length_is_rejected_with_bad_request() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("10"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("10"));
        assert_eq!(
            validate_declared_content_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn host_header_with_port_normalizes_to_hostname() {
        let value = HeaderValue::from_static("App.Example.com:8081");
        assert_eq!(normalize_host(&value).as_deref(), Some("app.example.com"));
    }

    #[test]
    fn host_header_with_trailing_dot_is_normalized() {
        let value = HeaderValue::from_static("app.example.com.");
        assert_eq!(normalize_host(&value).as_deref(), Some("app.example.com"));
    }

    #[test]
    fn invalid_host_header_is_rejected() {
        let value = HeaderValue::from_static("bad host:8080");
        assert!(normalize_host(&value).is_none());
    }

    #[test]
    fn connection_upgrade_token_is_detected_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(connection_requests_upgrade(&headers));
    }

    #[test]
    fn hop_by_hop_and_connection_nominated_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-private-hop"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-private-hop", HeaderValue::from_static("remove-me"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-private-hop"));
        assert!(headers.contains_key(CONTENT_TYPE));
    }
}

#[cfg(test)]
mod quantum_shield_post_quantum_handshake_regression {
    use super::{load_tls_server_config, quantum_shield_crypto_provider};
    use std::{
        fs,
        io::Cursor,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn pqc_policy_defaults_to_strict_and_rejects_unknown_values() {
        assert!(super::quantum_shield_pqc_strict_from_value(None).unwrap());
        assert!(!super::quantum_shield_pqc_strict_from_value(Some("prefer")).unwrap());
        assert!(super::quantum_shield_pqc_strict_from_value(Some("strict")).unwrap());
        assert!(super::quantum_shield_pqc_strict_from_value(Some("disabled")).is_err());
    }

    #[test]
    fn strict_pqc_provider_exposes_only_x25519mlkem768() {
        let provider = super::quantum_shield_crypto_provider_for_mode(true).unwrap();
        let names: Vec<String> = provider
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect();

        assert_eq!(
            names,
            vec!["X25519MLKEM768"],
            "strict mode must not offer a classical key-exchange fallback"
        );
        assert!(
            provider
                .cipher_suites
                .iter()
                .all(|suite| suite.version() == &rustls::version::TLS13),
            "strict mode must not include TLS 1.2 cipher suites"
        );
    }

    #[test]
    fn provider_offers_multiple_mlkem_key_exchange_groups() {
        let provider = quantum_shield_crypto_provider();
        let names: Vec<String> = provider
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect();

        for expected in [
            "X25519MLKEM768",
            "secp256r1MLKEM768",
            "MLKEM768",
            "MLKEM1024",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "configured AWS-LC provider does not offer {expected}; groups: {names:?}"
            );
        }

        assert_eq!(
            names.first().map(String::as_str),
            Some("X25519MLKEM768"),
            "the existing hybrid key-exchange preference must remain first"
        );
    }

    #[test]
    fn local_server_negotiates_x25519mlkem768() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();

        let directory =
            std::env::temp_dir().join(format!("qs-pq-handshake-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).expect("create test directory");
        let _cleanup = TemporaryDirectory(directory.clone());

        let cert_path = directory.join("localhost-cert.pem");
        let key_path = directory.join("localhost-key.pem");

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate synthetic localhost certificate");

        fs::write(&cert_path, generated.cert.pem()).expect("write test certificate");
        fs::write(&key_path, generated.key_pair.serialize_pem()).expect("write test key");
        fs::set_permissions(
            &key_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .expect("restrict temporary test-key permissions");

        // Exercise the project's actual server configuration loader.
        #[cfg(feature = "mTls")]
        let (client_roots, client_identity) = {
            use rcgen::{
                BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            };
            let mut ca_params =
                CertificateParams::new(Vec::<String>::new()).expect("valid empty CA parameter set");
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "qs test client CA");
            let ca_key = KeyPair::generate().expect("generate test CA key");
            let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign test CA");

            let mut client_params = CertificateParams::new(vec!["client.example".to_owned()])
                .expect("valid client parameter set");
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client_key = KeyPair::generate().expect("generate client key");
            let client_cert = client_params
                .signed_by(&client_key, &ca_cert, &ca_key)
                .expect("sign client certificate");

            let ca_path = directory.join("client-ca.pem");
            fs::write(&ca_path, ca_cert.pem()).expect("write client CA");
            std::env::set_var("QUANTUM_SHIELD_MTLS_CA", &ca_path);

            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(generated.cert.der().clone())
                .expect("trust test certificate");
            roots.add(ca_cert.der().clone()).expect("trust client CA");
            let identity = (
                vec![client_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
            );
            (roots, identity)
        };

        let server_config = load_tls_server_config(&cert_path, &key_path)
            .expect("load project TLS server configuration");

        #[cfg(not(feature = "mTls"))]
        let mut roots = rustls::RootCertStore::empty();
        #[cfg(not(feature = "mTls"))]
        roots
            .add(generated.cert.der().clone())
            .expect("trust test certificate");

        #[cfg(feature = "mTls")]
        let (roots, identity) = (client_roots, client_identity);

        let client_builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        #[cfg(feature = "mTls")]
        let client_config = client_builder
            .with_client_auth_cert(identity.0, identity.1)
            .expect("configure client identity");
        #[cfg(not(feature = "mTls"))]
        let client_config = client_builder.with_no_client_auth();

        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
            .expect("valid test server name");

        let mut client =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                .expect("create client connection");

        let mut server =
            rustls::ServerConnection::new(server_config).expect("create server connection");

        // Transfer real TLS records through in-memory I/O until the handshake ends.
        for _ in 0..32 {
            let mut client_wire = Vec::new();
            client
                .write_tls(&mut client_wire)
                .expect("client TLS write");

            if !client_wire.is_empty() {
                server
                    .read_tls(&mut Cursor::new(client_wire))
                    .expect("server TLS read");
                server
                    .process_new_packets()
                    .expect("process client packets");
            }

            let mut server_wire = Vec::new();
            server
                .write_tls(&mut server_wire)
                .expect("server TLS write");

            if !server_wire.is_empty() {
                client
                    .read_tls(&mut Cursor::new(server_wire))
                    .expect("client TLS read");
                client
                    .process_new_packets()
                    .expect("process server packets");
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }

        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "TLS handshake did not complete"
        );

        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "expected TLS 1.3"
        );

        let negotiated = server
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name()));

        eprintln!("Actual negotiated TLS key-exchange group: {negotiated:?}");

        assert_eq!(
            negotiated.as_deref(),
            Some("X25519MLKEM768"),
            "hybrid post-quantum key exchange was not negotiated"
        );
    }
}

#[cfg(test)]
mod quantum_shield_user_agent_policy_tests {
    use super::user_agent_matches_blocklist;
    use http::HeaderValue;

    fn patterns(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn configured_crawler_substrings_are_blocked_case_insensitively() {
        let rules = patterns(&["GPTBot", "ClaudeBot", "Google-Extended"]);
        let user_agent = HeaderValue::from_static("Mozilla/5.0 GPTBot/1.0");

        assert!(user_agent_matches_blocklist(Some(&user_agent), &rules));
    }

    #[test]
    fn unlisted_browser_user_agent_is_allowed() {
        let rules = patterns(&["GPTBot", "ClaudeBot"]);
        let user_agent = HeaderValue::from_static("Mozilla/5.0 ExampleBrowser/1.0");

        assert!(!user_agent_matches_blocklist(Some(&user_agent), &rules));
    }

    #[test]
    fn empty_policy_does_not_block_requests() {
        let user_agent = HeaderValue::from_static("Mozilla/5.0 GPTBot/1.0");
        assert!(!user_agent_matches_blocklist(Some(&user_agent), &[]));
    }

    #[test]
    fn absent_user_agent_does_not_crash() {
        assert!(!user_agent_matches_blocklist(None, &patterns(&["GPTBot"])));
    }

    #[test]
    fn empty_entries_do_not_match_every_request() {
        let rules = patterns(&["", "   "]);
        let user_agent = HeaderValue::from_static("Mozilla/5.0 ExampleBrowser/1.0");
        assert!(!user_agent_matches_blocklist(Some(&user_agent), &rules));
    }
}

#[cfg(test)]
mod websocket_compatibility_tests {
    use super::{reject_uninspected_websocket, valid_websocket_handshake};
    use http::{
        header::{CONNECTION, UPGRADE},
        HeaderMap, HeaderValue, Method, StatusCode, Version,
    };

    fn valid_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        h.insert("sec-websocket-version", HeaderValue::from_static("13"));
        h.insert(
            "sec-websocket-key",
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        h
    }

    #[test]
    fn uninspected_websocket_upgrades_fail_closed() {
        let rejection =
            reject_uninspected_websocket(true).expect("uninspected WebSocket must be rejected");
        assert_eq!(rejection.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(reject_uninspected_websocket(false).is_none());
    }

    #[test]
    fn accepts_standard_websocket_handshake() {
        assert!(valid_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &valid_headers()
        ));
    }

    #[test]
    fn rejects_bad_key_version_body_framing_and_method() {
        let mut h = valid_headers();
        h.insert(
            "sec-websocket-key",
            HeaderValue::from_static("not-a-valid-key"),
        );
        assert!(!valid_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &h
        ));

        let mut h = valid_headers();
        h.insert("sec-websocket-version", HeaderValue::from_static("12"));
        assert!(!valid_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &h
        ));

        let mut h = valid_headers();
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert!(!valid_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &h
        ));

        assert!(!valid_websocket_handshake(
            &Method::POST,
            Version::HTTP_11,
            &valid_headers()
        ));
    }

    #[test]
    fn rejects_handshake_without_connection_upgrade_token() {
        let mut h = valid_headers();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        assert!(!valid_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &h
        ));
    }
}

#[cfg(test)]
mod waf_regression_tests {
    use super::*;

    #[test]
    fn configured_waf_file_failure_is_not_silently_ignored() {
        let path = format!(
            "/tmp/qs-waf-config-must-not-exist-{}.conf",
            std::process::id()
        );
        assert!(
            !std::path::Path::new(&path).exists(),
            "test path unexpectedly already exists"
        );

        match super::build_quantum_shield_waf(Some(&path)) {
            Ok(_) => panic!("missing configured WAF file must not load successfully"),
            Err(error) => assert!(
                error.contains("failed to load configured WAF rules"),
                "unexpected error: {error}"
            ),
        }
    }

    fn test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("qs-lab.test"));
        headers
    }

    #[test]
    fn rejects_unsigned_bearer_jwt() {
        let mut headers = test_headers();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            ),
        );
        assert!(has_unsigned_bearer_jwt(&headers));
    }

    #[test]
    fn does_not_classify_signed_jwt_as_unsigned() {
        let mut headers = test_headers();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature"),
        );
        assert!(!has_unsigned_bearer_jwt(&headers));
    }

    #[test]
    fn ignores_non_bearer_authorization_schemes() {
        let mut headers = test_headers();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "Basic eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            ),
        );
        assert!(!has_unsigned_bearer_jwt(&headers));
    }

    #[test]
    fn waf_blocks_path_traversal() {
        let result = inspect_waf_request("GET", "/download/../../etc/passwd", &test_headers(), b"")
            .expect("WAF evaluation should succeed");
        assert_eq!(result.map(|item| item.0), Some(403));
    }

    #[test]
    fn waf_blocks_sensitive_configuration_paths() {
        let result = inspect_waf_request("GET", "/.env", &test_headers(), b"")
            .expect("WAF evaluation should succeed");
        assert_eq!(result.map(|item| item.0), Some(403));
    }

    #[test]
    fn waf_rejects_trace_method() {
        let result = inspect_waf_request("TRACE", "/", &test_headers(), b"")
            .expect("WAF evaluation should succeed");
        assert_eq!(result.map(|item| item.0), Some(403));
    }

    #[test]
    fn waf_blocks_shell_substitution_in_arguments() {
        let result = inspect_waf_request("GET", "/search?q=%24%28id%29", &test_headers(), b"")
            .expect("WAF evaluation should succeed");
        assert_eq!(result.map(|item| item.0), Some(403));
    }

    #[test]
    fn authentication_rate_limit_is_stricter_than_general_limit() {
        let ip = "192.0.2.10".parse().unwrap();
        let start = std::time::Instant::now();
        let mut windows = std::collections::HashMap::new();

        for _ in 0..QS_AUTH_REQUESTS_PER_MINUTE {
            assert!(quantum_shield_consume_rate_slot(
                &mut windows,
                ip,
                QuantumShieldRateClass::Authentication,
                QS_AUTH_REQUESTS_PER_MINUTE,
                start,
            ));
        }

        assert!(!quantum_shield_consume_rate_slot(
            &mut windows,
            ip,
            QuantumShieldRateClass::Authentication,
            QS_AUTH_REQUESTS_PER_MINUTE,
            start,
        ));

        assert!(quantum_shield_consume_rate_slot(
            &mut windows,
            ip,
            QuantumShieldRateClass::Authentication,
            QS_AUTH_REQUESTS_PER_MINUTE,
            start + QS_RATE_WINDOW,
        ));
    }

    #[test]
    fn rate_limit_budgets_are_isolated_between_client_ips() {
        let start = std::time::Instant::now();
        let mut windows = std::collections::HashMap::new();
        let first = "192.0.2.11".parse().unwrap();
        let second = "192.0.2.12".parse().unwrap();

        for _ in 0..QS_AUTH_REQUESTS_PER_MINUTE {
            assert!(quantum_shield_consume_rate_slot(
                &mut windows,
                first,
                QuantumShieldRateClass::Authentication,
                QS_AUTH_REQUESTS_PER_MINUTE,
                start,
            ));
        }

        assert!(quantum_shield_consume_rate_slot(
            &mut windows,
            second,
            QuantumShieldRateClass::Authentication,
            QS_AUTH_REQUESTS_PER_MINUTE,
            start,
        ));
    }

    #[test]
    fn identifies_authentication_endpoints_for_stricter_limits() {
        assert!(quantum_shield_is_authentication_endpoint(
            "/rest/user/login"
        ));
        assert!(quantum_shield_is_authentication_endpoint("/api/token"));
        assert!(quantum_shield_is_authentication_endpoint("/password/reset"));
        assert!(!quantum_shield_is_authentication_endpoint(
            "/rest/products/search"
        ));
    }

    #[test]
    fn waf_still_allows_a_benign_api_request() {
        let result =
            inspect_waf_request("GET", "/rest/products/search?q=apple", &test_headers(), b"")
                .expect("WAF evaluation should succeed");
        assert_eq!(result, None);
    }

    #[test]
    fn rejects_unsigned_jwt_in_token_cookie() {
        let mut headers = test_headers();
        headers.insert(
            "cookie",
            HeaderValue::from_static(
                "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            ),
        );
        assert!(has_unsigned_jwt_credential(&headers, None));
    }

    #[test]
    fn rejects_unsigned_jwt_in_query_token() {
        let headers = test_headers();
        let query = "access_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";
        assert!(has_unsigned_jwt_credential(&headers, Some(query)));
    }

    #[test]
    fn rejects_none_algorithm_even_with_nonempty_signature() {
        assert!(token_uses_unsigned_jwt_algorithm(
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.arbitrary"
        ));
    }

    #[test]
    fn waf_allows_normal_product_search() {
        let decision =
            inspect_waf_request("GET", "/rest/products/search?q=apple", &test_headers(), b"")
                .expect("WAF engine should initialize and process a benign request");

        assert_eq!(decision, None);
    }

    #[test]
    fn waf_blocks_sql_injection_in_query_arguments() {
        let decision = inspect_waf_request(
            "GET",
            "/rest/products/search?q=%27%20OR%201%3D1--",
            &test_headers(),
            b"",
        )
        .expect("WAF evaluation should succeed");

        assert!(decision.is_some(), "SQL injection query was not blocked");
    }

    #[test]
    fn waf_blocks_xss_in_query_arguments() {
        let decision = inspect_waf_request(
            "GET",
            "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            &test_headers(),
            b"",
        )
        .expect("WAF evaluation should succeed");

        assert!(decision.is_some(), "XSS query was not blocked");
    }

    #[test]
    fn waf_blocks_sql_injection_in_json_body() {
        let mut headers = test_headers();
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let body = br#"{"email":"' OR 1=1--","password":"neutral-test-value"}"#;

        let decision = inspect_waf_request("POST", "/rest/user/login", &headers, body)
            .expect("WAF body evaluation should succeed");

        assert!(decision.is_some(), "SQL injection body was not blocked");
    }
}

#[cfg(all(test, feature = "mTls"))]
mod mtls_regression_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mtls_requires_nonempty_client_ca_bundle() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qs-mtls-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test directory");

        let empty = dir.join("empty.pem");
        fs::write(&empty, b"").expect("write empty bundle");
        assert!(
            mtls_client_verifier_from_bundle(&empty).is_err(),
            "an empty client CA bundle must fail closed"
        );

        let generated = rcgen::generate_simple_self_signed(vec!["client.example".to_owned()])
            .expect("generate test CA");
        let ca = dir.join("ca.pem");
        fs::write(&ca, generated.cert.pem()).expect("write CA bundle");
        assert!(
            mtls_client_verifier_from_bundle(&ca).is_ok(),
            "a valid PEM client CA must build a verifier"
        );

        fs::remove_dir_all(&dir).expect("clean test directory");
    }
}

#[cfg(all(test, feature = "prometheus"))]
mod prometheus_regression_tests {
    #[test]
    fn metrics_render_exposes_response_counter() {
        super::metrics::observe(403);
        let text = super::metrics::render();
        assert!(text.contains("quantum_shield_http_responses_total"));
        assert!(text.contains("403"));
    }
}

#[cfg(all(test, feature = "dlp"))]
mod dlp_proxy_regression_tests {
    use super::*;

    #[tokio::test]
    async fn live_response_path_redacts_text_and_fixes_content_length() {
        let mut response = Response::new(
            Full::new(Bytes::from_static(
                b"card 1234 5678 9012 3456 SQL STATE [42000]",
            ))
            .map_err(|never| match never {})
            .boxed_unsync(),
        );
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("43"));

        let filtered = dlp_filter_response(response).await;
        assert_eq!(filtered.status(), StatusCode::OK);
        let body = filtered
            .into_body()
            .collect()
            .await
            .expect("collect filtered body")
            .to_bytes();
        let text = std::str::from_utf8(&body).expect("DLP output stays UTF-8");
        assert!(!text.contains("1234 5678 9012 3456"));
        assert!(!text.contains("SQL STATE"));
        assert!(text.contains("[REDACTED-CARD]"));
    }

    #[tokio::test]
    async fn gzip_text_is_decompressed_inspected_and_redacted() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let plaintext = b"card 1234 5678 9012 3456 SQL STATE [42000]";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).expect("compress fixture");
        let compressed = encoder.finish().expect("finish gzip fixture");

        let mut response = Response::new(
            Full::new(Bytes::from(compressed))
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        response
            .headers_mut()
            .insert("content-encoding", HeaderValue::from_static("gzip"));

        let filtered = dlp_filter_response(response).await;
        assert_eq!(filtered.status(), StatusCode::OK);
        assert!(
            filtered.headers().get("content-encoding").is_none(),
            "decoded responses must not retain a stale Content-Encoding"
        );
        let body = filtered
            .into_body()
            .collect()
            .await
            .expect("collect filtered body")
            .to_bytes();
        let text = std::str::from_utf8(&body).expect("DLP output stays UTF-8");
        assert!(!text.contains("1234 5678 9012 3456"));
        assert!(!text.contains("SQL STATE"));
        assert!(text.contains("[REDACTED-CARD]"));
    }

    #[tokio::test]
    async fn unsupported_content_encoding_fails_closed() {
        let mut response = Response::new(
            Full::new(Bytes::from_static(b"secret"))
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        response
            .headers_mut()
            .insert("content-encoding", HeaderValue::from_static("br"));
        assert_eq!(
            dlp_filter_response(response).await.status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
