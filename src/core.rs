//! # Endpoint Core Logic & Library API
//!
//! This module implements the primary logic for the client application. It serves two purposes:
//!
//! 1.  **Standalone Client Core**: The `run_client` function provides an all-in-one, self-contained
//!     client application logic, suitable for simple binaries like `client01` and `client02`.
//!
//! 2.  **Reusable Library API**: For more flexible integration into other applications, this module
//!     exposes a library-style API centered around the `SpnEndpoint`.
//!
//! ## Library Usage
//!
//! To use this crate as a library, follow these steps:
//!
//! 1.  Call `create_spn_endpoint` with your configuration to initialize the provider.
//!     This will start background tasks to manage QUIC connections.
//! 2.  To **open** a client-initiated stream, call `SpnEndpoint::open_stream`.
//! 3.  To **accept** a server-initiated stream, call `SpnEndpoint::accept_stream`.
//! 4.  The `SpnEndpoint` handle manages the lifecycle. When it is dropped, all background
//!     tasks are automatically shut down.
//!
//! ### Example
//!
//! The following example demonstrates how to open a client-initiated stream and
//! simultaneously listen for server-initiated streams in a separate task.
//!
//! ```no_run
//! # use qtest5eventdclient_multi::client_core::create_spn_endpoint;
//! # use tokio::io::AsyncWriteExt;
//! # use std::sync::Arc;
//! # use tracing::info;
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Wrap the provider in an Arc to share it between tasks.
//! let provider = Arc::new(create_spn_endpoint(
//!     "example.com",
//!     4433,
//!     "path/to/cert.pem",
//!     "path/to/key.pem",
//!     "path/to/ca.pem",
//! ).await?);
//!
//! // --- Accepting Server-Initiated Streams ---
//! // Spawn a task to handle incoming streams from the server.
//! let provider_clone = provider.clone();
//! tokio::spawn(async move {
//!     loop {
//!         info!("Waiting to accept a server-initiated stream...");
//!         match provider_clone.accept_stream().await {
//!             Ok((_send, _recv, _guard)) => {
//!                 info!("Accepted a server-initiated stream!");
//!                 // Handle the stream...
//!             }
//!             Err(e) => {
//!                 info!("Error accepting stream: {}. Listener task shutting down.", e);
//!                 break;
//!             }
//!         }
//!     }
//! });
//!
//! // --- Opening Client-Initiated Streams ---
//! // In the main task, open a client-initiated stream.
//! info!("Opening a client-initiated stream...");
//! let (mut send_stream, _recv_stream, _guard) = provider.open_stream().await?;
//! send_stream.write_all(b"hello from client").await?;
//! info!("Client-initiated stream opened and data sent.");
//!
//! // The provider will shut down automatically when the Arc's strong count
//! // reaches zero (i.e., when both the main task and the listener task finish).
//! # tokio::time::sleep(std::time::Duration::from_millis(100)).await; // Give spawned task time to run
//! # Ok(())
//! # }
//! ```
//!
//! # history
//! - multiple hub support
//! - multiple provider support, provider select
//! - quic stream re-connect support
//! - graceful down
//!
//! # To Do
//! - Investigate using DashMap for the connection pool.
//! - Check if the number of Tokio tasks in the consumer crate is decreasing too slowly.
//!
//! # Considerations
//! For copying data between two streams, we evaluated `tokio::io::copy_bidirectional` against
//! a custom implementation using `tokio::select!`, `join!`, or `try_join!`. The decision
//! is based on a trade-off between robustness, counter accuracy, error detail, performance,
//! and code simplicity.

use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, AtomicU8, Ordering},
};
use std::time::Instant;

use chrono::Utc;
use quinn::{ReadExactError, RecvStream, SendStream};
use rand::seq::SliceRandom;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::Instrument;
use tracing::info_span;
use tracing::{error, info, trace, warn};

use crate::common;
use crate::common::create_quic_client_endpoint;

//======================================================================
//== Public Library API
//======================================================================

/// RAII guard for stream counting.
/// Decrements the count when dropped.
///
/// **Important:** You must keep this guard alive as long as the stream is active.
/// Dropping it early will decrement the active stream count, potentially causing
/// the connection to be closed prematurely during a graceful shutdown.
#[derive(Debug)]
pub struct StreamGuard {
    count: Arc<AtomicUsize>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let prev = self.count.fetch_sub(1, Ordering::Relaxed);
        trace!("Stream guard dropped. Active streams: {}", prev.saturating_sub(1));
    }
}

/// Manages the lifecycle of QUIC connections and provides an interface for creating streams.
///
/// This is the primary handle for using the client library. An instance is created by
/// calling [`create_spn_endpoint`]. It holds all necessary state and manages
/// background tasks for connection maintenance.
///
/// When this struct is dropped, it automatically signals all background tasks to shut down
/// gracefully, ensuring a clean exit (RAII).

#[derive(Debug)]
pub struct SpnEndpoint {
    /// The QUIC endpoint handle, retained to ensure proper closure on drop.
    endpoint: quinn::Endpoint,
    /// Shared dictionary of active QUIC connections.
    hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
    /// Handle to the main background maintenance task.
    hub_connections_maintenance_task: JoinHandle<()>,
    /// Handle to the background activity monitoring task.
    activity_monitor_task: JoinHandle<()>,
    /// Queue for server-initiated streams, ready to be accepted by the user.
    accepted_stream_queue: Arc<Mutex<VecDeque<(SendStream, RecvStream, StreamGuard)>>>,
    /// Notification for when a new stream is added to the queue.
    accepted_stream_notify: Arc<Notify>,
}

impl Drop for SpnEndpoint {
    fn drop(&mut self) {
        info!("SpnEndpoint is being dropped, initiating shutdown.");
        // This performs a forceful shutdown. Unlike the `run_client_*` functions,
        // we cannot await graceful draining here because `Drop` is synchronous.

        // Abort the main maintenance task itself as a final measure.
        self.hub_connections_maintenance_task.abort();

        // Abort the activity monitor task.
        self.activity_monitor_task.abort();

        // Explicitly close the endpoint. This ensures that any detached connection tasks
        // (which hold clones of the endpoint) are forced to terminate.
        self.endpoint.close(0u32.into(), b"SpnEndpoint dropped");
    }
}

impl SpnEndpoint {
    /// Waits for and accepts a new server-initiated bidirectional stream.
    ///
    /// This function is passive; it waits until the server opens a new stream on any of
    /// the established connections. This is useful for server-push scenarios.
    ///
    /// # Errors
    /// This function will return an error if the underlying provider is shut down
    /// and no more streams can be received.
    ///
    /// # Returns
    /// A `Result` containing a tuple of `(SendStream, RecvStream, StreamGuard)` on success.
    /// The `StreamGuard` must be kept alive as long as the stream is in use.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream, StreamGuard), Box<dyn Error>> {
        loop {
            let mut q = self.accepted_stream_queue.lock().await;
            if let Some(stream) = q.pop_front() {
                return Ok(stream);
            }
            drop(q);
            self.accepted_stream_notify.notified().await;
        }
    }

    /// Opens a new QUIC stream on the best available connection.
    ///
    /// This method is the primary way to obtain a communication channel from the provider.
    /// It first waits for a QUIC connection to be established if none are available,
    /// with a reasonable timeout. Once a connection is ready, it selects a suitable one
    /// from the internal pool based on a predefined strategy (e.g., lowest latency)
    /// and opens a new bidirectional stream on it.
    ///
    /// # Errors
    /// This function will return an error if no active QUIC connections are available
    /// or if opening a new stream on the selected connection fails.
    ///
    /// # Returns
    /// A `Result` containing a tuple of `(SendStream, RecvStream, StreamGuard)` on success.
    /// The `StreamGuard` must be kept alive as long as the stream is in use.
    pub async fn open_stream(
        &self,
    ) -> Result<(SendStream, RecvStream, StreamGuard), Box<dyn Error + Send + Sync>> {
        info!("Requesting a new QUIC stream from the provider.");
        let stream = open_stream_on_best_connection(
            self.hub_connections.clone(),
            ConnectionSelectionStrategy::Random,
        )
        .await?;
        Ok(stream)
    }
}

/// Creates and initializes an `SpnEndpoint`, launching the background tasks
/// required for maintaining QUIC connections.
///
/// This function is the main entry point for using this crate as a library.
/// It performs all the necessary setup, including certificate loading and QUIC endpoint
/// configuration, before spawning the connection maintenance loop in the background.
///
/// # Arguments
/// * `spn_hub_url`: The URL name of the spn server to connect to.
/// * `cert_path`: Path to the client's certificate PEM file.
/// * `key_path`: Path to the client's private key PEM file.
/// * `trust_store_path`: Path to the trusted CA certificate(s) PEM file for server verification.
/// * `alpn`: A slice of supported ALPN protocols to advertise to the server.
/// * `endpoint_type`: The type of endpoint (e.g., "provider", "consumer").
///
/// # Returns
/// A `Result` containing an `SpnEndpoint` instance on success, or an error if
/// initialization fails (e.g., due to invalid certificate paths).
pub async fn create_spn_endpoint(
    spn_hub_url: &'static str,
    cert_path: &'static str,
    key_path: &'static str,
    trust_store_path: &'static str,
    alpn: &'static [&'static [u8]],
    endpoint_type: &'static str,
) -> Result<SpnEndpoint, Box<dyn Error>> {
    let parsed_url = url::Url::parse(spn_hub_url).expect("Failed to parse URL");
    let host_slice = parsed_url
        .host_str()
        .expect("Could not find a server name (host) in the URL.");
    let server_name: &'static str = Box::leak(host_slice.to_string().into_boxed_str());
    let server_port: u16 = parsed_url
        .port_or_known_default()
        .expect("Could not determine the port number.");

    // The library user is responsible for setting up tracing.
    common::initialize_crypto_provider();

    let (certs, key, truststore) =
        common::load_certs_and_key(cert_path, key_path, trust_store_path)?;

    let endpoint = create_quic_client_endpoint(certs, key, truststore, alpn)?;

    // Shared state for the provider and its background tasks.
    let hub_connections = Arc::new(RwLock::new(HashMap::<SocketAddr, HubConnection>::new()));
    // Channel for streams accepted from the server, to be passed to the library user.
    let accepted_stream_queue = Arc::new(Mutex::new(VecDeque::new()));
    let accepted_stream_notify = Arc::new(Notify::new());

    // Start the activity monitor task. This task will run in the background.
    let activity_monitor_task = tokio::spawn(HubConnectionManager::monitor_activity(
        hub_connections.clone(),
        Duration::from_secs(10),// Check for activity every 10 seconds.
        Duration::from_secs(30),// Log a warning if a connection is idle for more than 30 seconds.
    ));

    let stream_handler = LibraryStreamHandler {
        queue: accepted_stream_queue.clone(),
        notify: accepted_stream_notify.clone(),
        capacity: 128,
    };

    let hub_connections_maintenance_task = spawn_connection_maintenance_task(
        server_name.to_string(),
        server_port,
        endpoint.clone(),
        stream_handler,
        hub_connections.clone(),
        endpoint_type,
    );

    Ok(SpnEndpoint {
        endpoint,
        hub_connections,
        hub_connections_maintenance_task,
        activity_monitor_task,
        accepted_stream_queue,
        accepted_stream_notify,
    })
}

//======================================================================
//== Endpoint Agent Binary API
//======================================================================

/// The all-in-one entry point for running a provider application.
///
/// This function encapsulates the entire client lifecycle, including setup,
/// the main event loop (DNS checks, TCP listening, signal handling), and graceful shutdown.
/// It is primarily intended for simple, standalone binaries like `client01` and `client02`.
///
/// # Arguments
/// * `config`: An `AppConfig` struct containing all necessary configuration for this client instance.
#[doc(hidden)]
pub async fn run_client_consumer(
    server_name: &str,
    server_port: u16,
    trust_store_path: &str,
    cert_path: &str,
    key_path: &str,
    tcp_bind_address: &str,
) -> Result<(), Box<dyn Error>> {
    common::setup_tracing();
    common::initialize_crypto_provider();

    // Initialize signal handlers early to fail fast if they cannot be registered.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("Failed to install SIGINT handler");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
        .expect("Failed to install SIGQUIT handler");
    info!(
        "Consumer Client started (PID: {}) with config for: {}, {}, {}, {}, {}, {}",
        std::process::id(),
        server_name, server_port, trust_store_path, cert_path, key_path, tcp_bind_address
    );

    let (cert_path, key_path, trust_store_path) =
        common::load_certs_and_key(cert_path, key_path, trust_store_path)?;

    let endpoint =
        create_quic_client_endpoint(cert_path, key_path, trust_store_path, &[b"sc01-consumer"])?;

    // Dictionary to store active quic connections and their info, accessible from multiple tasks.
    let hub_connections = Arc::new(RwLock::new(HashMap::<SocketAddr, HubConnection>::new()));

    // Start the activity monitor task. This task will run in the background.
    let activity_monitor_task = tokio::spawn(HubConnectionManager::monitor_activity(
        hub_connections.clone(),
        Duration::from_secs(10),    // Check for activity every 10 seconds.
        Duration::from_secs(30),    // Log a warning if a connection is idle for more than 30 seconds.
    ));

    // Bind a TCP listener for local control.
    let listener = TcpListener::bind(tcp_bind_address).await?;
    info!(
        "Listening for local TCP control connections on {}",
        tcp_bind_address
    );

    // --- Task 1: Connection Maintenance (DNS & QUIC) ---
    // This task manages the lifecycle of QUIC connections to the Hub.
    let hub_connections_maintenance_task = spawn_connection_maintenance_task(
        server_name.to_string(),
        server_port,
        endpoint.clone(),
        ConsumerStreamHandler,
        hub_connections.clone(),
        "consumer",
    );

    // --- Task 2: TCP Listener Manager ---
    // This task accepts local TCP connections and manages proxy tasks.
    let tcp_listener_task = {
        let hub_connections = hub_connections.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, remote_addr)) => {
                        info!("Accepted TCP connection from: {}", remote_addr);
                        let strategy = ConnectionSelectionStrategy::LowestLatency;
                        let retry_config = ProxyRetryConfig::default();
                        tokio::spawn(
                            handle_new_tcp_connection(
                                tcp_stream,
                                remote_addr,
                                hub_connections.clone(),
                                strategy,
                                retry_config,
                            )
                            .instrument(info_span!("quic/tcp proxy session", client_addr = %remote_addr)),
                        );
                    }
                    Err(e) => {
                        error!("Failed to accept TCP connection: {}. Retrying in 1s...", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        })
    };

    // --- Main Thread Wait ---
    let graceful = tokio::select! {
        _ = sigint.recv() => {
            info!("SIGINT received. Initiating immediate shutdown.");
            false
        },
        _ = sigterm.recv() => {
            info!("SIGTERM received. Initiating graceful shutdown.");
            true
        },
        _ = sigquit.recv() => {
            info!("SIGQUIT received. Initiating immediate shutdown.");
            false
        },
    };

    // --- Final Cleanup ---
    info!("Executing final cleanup...");

    // Abort background tasks immediately.
    hub_connections_maintenance_task.abort();
    tcp_listener_task.abort();
    activity_monitor_task.abort();

    // Perform graceful shutdown of QUIC connections.
    if graceful {
        HubConnectionManager::graceful_shutdown_all(hub_connections).await;
    }

    endpoint.close(0u32.into(), b"shutting down");
    endpoint.wait_idle().await;
    info!("Shutdown complete.");

    // Add a small delay to allow background tasks to finish logging before the main process exits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

// consumer
#[doc(hidden)]
pub async fn run_client_provider(
    server_name: &str,
    server_port: u16,
    trust_store_path: &str,
    cert_path: &str,
    key_path: &str,
    tcp_bind_address: &str,
) -> Result<(), Box<dyn Error>> {
    common::setup_tracing();
    common::initialize_crypto_provider();

    // Initialize signal handlers early to fail fast if they cannot be registered.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("Failed to install SIGINT handler");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
        .expect("Failed to install SIGQUIT handler");
    info!(
        "Provider Client started (PID: {}) with config for: {}, {}, {}, {}, {}, {}",
        std::process::id(),
        server_name, server_port, trust_store_path, cert_path, key_path, tcp_bind_address
    );

    let (cert_path, key_path, trust_store_path) =
        common::load_certs_and_key(cert_path, key_path, trust_store_path)?;

    let endpoint =
        create_quic_client_endpoint(cert_path, key_path, trust_store_path, &[b"sc01-provider"])?;

    // Dictionary to store active quic connections and their info, accessible from multiple tasks.
    let hub_connections = Arc::new(RwLock::new(HashMap::<SocketAddr, HubConnection>::new()));

    // Start the activity monitor task. This task will run in the background.
    let activity_monitor_task = tokio::spawn(HubConnectionManager::monitor_activity(
        hub_connections.clone(),    // Check for activity every 10 seconds.
        Duration::from_secs(10),    // Log a warning if a connection is idle for more than 30 seconds.
        Duration::from_secs(30),
    ));

    // --- Task 1: Connection Maintenance (DNS & QUIC) ---
    let stream_handler = ProviderStreamHandler {
        tcp_bind_address: tcp_bind_address.to_string(),
    };

    let hub_connections_maintenance_task = spawn_connection_maintenance_task(
        server_name.to_string(),
        server_port,
        endpoint.clone(),
        stream_handler,
        hub_connections.clone(),
        "provider",
    );

    // --- Main Thread Wait ---
    let graceful = tokio::select! {
        _ = sigint.recv() => {
            info!("SIGINT received. Initiating immediate shutdown.");
            false
        },
        _ = sigterm.recv() => {
            info!("SIGTERM received. Initiating graceful shutdown.");
            true
        },
        _ = sigquit.recv() => {
            info!("SIGQUIT received. Initiating immediate shutdown.");
            false
        },
    };

    // --- Final Cleanup ---
    info!("Executing final cleanup...");

    // Abort background tasks.
    hub_connections_maintenance_task.abort();
    activity_monitor_task.abort();

    // Perform graceful shutdown of QUIC connections.
    if graceful {
        HubConnectionManager::graceful_shutdown_all(hub_connections).await;
    }

    endpoint.close(0u32.into(), b"shutting down");
    endpoint.wait_idle().await;
    info!("Shutdown complete.");

    // Add a small delay to allow background tasks to finish logging before the main process exits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

//======================================================================
//== Internal Helper Functions
//======================================================================

/// Handles an incoming TCP connection by proxying it over a QUIC stream with retry logic.
///
/// This function maintains the TCP connection while attempting to establish and
/// re-establish a QUIC stream if it disconnects. It includes limits for both
/// the number of retries and the total session time.
async fn handle_new_tcp_connection(
    tcp_stream: TcpStream,
    remote_addr: SocketAddr,
    hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
    strategy: ConnectionSelectionStrategy,
    retry_config: ProxyRetryConfig,
) {
    info!(
        "TCP client {} connected. Starting proxy session with retry logic.",
        remote_addr
    );

    let session_start = Instant::now();
    // Split the TCP stream once at the beginning. These halves will be used across all retries.
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

    for attempt in 0..=retry_config.max_retries {
        // Check for total session timeout at the beginning of each attempt.
        if attempt > 0 && session_start.elapsed() > retry_config.total_timeout {
            error!(
                "Proxy session for {} timed out after {:?}. Closing connection.",
                remote_addr, retry_config.total_timeout
            );
            return;
        }

        info!(
            "[Attempt {}/{}] Trying to open a QUIC stream for TCP client {}.",
            attempt + 1,
            retry_config.max_retries + 1,
            remote_addr
        );

        let quic_streams = match open_stream_on_best_connection(hub_connections.clone(), strategy).await
        {
            Ok(streams) => {
                info!(
                    "Successfully opened a QUIC stream for TCP client {}. Starting proxy session.",
                    remote_addr
                );
                streams
            }
            Err(e) => {
                warn!(
                    "Failed to open QUIC stream for {}: {}. Retrying...",
                    remote_addr, e
                );
                if attempt < retry_config.max_retries {
                    tokio::time::sleep(retry_config.retry_delay).await;
                    continue;
                } else {
                    error!(
                        "Failed to establish a QUIC stream for {} after all attempts. Closing TCP connection.",
                        remote_addr
                    );
                    return;
                }
            }
        };

        let (quic_send, quic_recv, _guard) = quic_streams;
        match copy_bidirectional_with_status(
            &mut tcp_read,
            &mut tcp_write,
            quic_send,
            quic_recv,
            remote_addr,
        )
        .await
        {
            Ok((tcp_read_bytes, tcp_written_bytes, quic_read_bytes, quic_written_bytes)) => {
                info!(
                    "Proxy for {} finished gracefully. Bytes (TCP Read -> QUIC Written): {} -> {}, (QUIC Read -> TCP Written): {} -> {}.",
                    remote_addr,
                    tcp_read_bytes,
                    quic_written_bytes,
                    quic_read_bytes,
                    tcp_written_bytes
                );
                return; // TCP connection closed, session is over.
            }
            Err(proxy_error) => {
                match proxy_error {
                    ProxyError::TcpStreamError { error, bytes } => {
                        let (
                            tcp_read_bytes,
                            tcp_written_bytes,
                            quic_read_bytes,
                            quic_written_bytes,
                        ) = bytes;
                        error!(
                            "Unrecoverable TCP error for {}: {}. Closing session. Bytes (TCP R->Q W): {}->{}, (QUIC R->TCP W): {}->{}.",
                            remote_addr,
                            error,
                            tcp_read_bytes,
                            quic_written_bytes,
                            quic_read_bytes,
                            tcp_written_bytes
                        );
                        return; // Non-recoverable TCP error, session is over.
                    }
                    ProxyError::QuicStreamReadError { error, bytes } => {
                        let (
                            tcp_read_bytes,
                            tcp_written_bytes,
                            quic_read_bytes,
                            quic_written_bytes,
                        ) = bytes;
                        warn!(
                            "Recoverable QUIC read error for {}: {}. Attempting to reconnect... Bytes (TCP R->Q W): {}->{}, (QUIC R->TCP W): {}->{}.",
                            remote_addr,
                            error,
                            tcp_read_bytes,
                            quic_written_bytes,
                            quic_read_bytes,
                            tcp_written_bytes
                        );
                    }
                    ProxyError::QuicStreamWriteError { error, bytes } => {
                        let (
                            tcp_read_bytes,
                            tcp_written_bytes,
                            quic_read_bytes,
                            quic_written_bytes,
                        ) = bytes;
                        warn!(
                            "Recoverable QUIC write error for {}: {}. Attempting to reconnect... Bytes (TCP R->Q W): {}->{}, (QUIC R->TCP W): {}->{}.",
                            remote_addr,
                            error,
                            tcp_read_bytes,
                            quic_written_bytes,
                            quic_read_bytes,
                            tcp_written_bytes
                        );
                    }
                }
            }
        }

        if attempt < retry_config.max_retries {
            tokio::time::sleep(retry_config.retry_delay).await;
        }
    }

    error!(
        "Failed to establish a stable QUIC stream for {} after all retries. Closing TCP connection.",
        remote_addr
    );
}

/// Copies data bidirectionally between TCP and QUIC streams, reporting status and detailed byte counts.
///
/// This function uses a two-task approach with `tokio::try_join!`. This prioritizes
/// fail-fast behavior: if an error occurs in either copy direction, the other direction
/// is immediately cancelled, and the function returns the error.
///
/// Per the design, byte counts are only guaranteed to be accurate on successful completion
/// of both streams. If an error occurs, the byte counts in the returned `ProxyError`
/// will be zero, as the state of the cancelled task is not available.
///
/// # Returns
/// A `Result` containing a tuple of four byte counts on success:
/// `(tcp_bytes_read, tcp_bytes_written, quic_bytes_read, quic_bytes_written)`.
/// On failure, it returns a structured `ProxyError` with zeroed byte counts.
async fn copy_bidirectional_with_status(
    tcp_read: &mut ReadHalf<TcpStream>,
    tcp_write: &mut WriteHalf<TcpStream>,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    remote_addr: SocketAddr,
) -> Result<(u64, u64, u64, u64), ProxyError> {
    trace!(
        "Starting a new bidirectional copy with status reporting for {}",
        remote_addr
    );

    // A simple internal error type to propagate the error source from the copy tasks.
    #[derive(Debug)]
    enum CopyError {
        Tcp(std::io::Error),
        QuicRead(quinn::ReadError),
        QuicWrite(quinn::WriteError),
    }

    // --- Task 1: Copy from TCP to QUIC ---
    // This task returns its byte counts on success, or an error on failure.
    let tcp_to_quic = async {
        let mut tcp_bytes_read = 0;
        let mut quic_bytes_written = 0;
        let mut buf = vec![0u8; common::PROXY_BUFFER_SIZE];

        loop {
            let n = match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    trace!(
                        "TCP -> QUIC: Connection closed by client {} (EOF).",
                        remote_addr
                    );
                    let _ = quic_send.finish();
                    break; // Graceful close, exit loop
                }
                Ok(n) => n,
                Err(e) => return Err(CopyError::Tcp(e)),
            };
            tcp_bytes_read += n as u64;

            if let Err(e) = quic_send.write_all(&buf[..n]).await {
                return Err(CopyError::QuicWrite(e));
            }
            quic_bytes_written += n as u64;
        }
        Ok((tcp_bytes_read, quic_bytes_written))
    };

    // --- Task 2: Copy from QUIC to TCP ---
    // This task also returns its byte counts on success, or an error on failure.
    let quic_to_tcp = async {
        let mut quic_bytes_read = 0;
        let mut tcp_bytes_written = 0;
        let mut buf = vec![0u8; common::PROXY_BUFFER_SIZE];

        loop {
            let n = match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => n,
                Ok(None) => {
                    trace!("QUIC -> TCP: Stream closed by peer for {}", remote_addr);
                    break; // Graceful close, exit loop
                }
                Err(e) => return Err(CopyError::QuicRead(e)),
            };
            quic_bytes_read += n as u64;

            if let Err(e) = tcp_write.write_all(&buf[..n]).await {
                return Err(CopyError::Tcp(e));
            }
            tcp_bytes_written += n as u64;
        }

        // Propagate FIN to TCP to support half-close correctly.
        if let Err(e) = tcp_write.shutdown().await {
            return Err(CopyError::Tcp(e));
        }

        Ok((quic_bytes_read, tcp_bytes_written))
    };

    // Wait for both tasks to complete. `try_join!` will fail fast if one returns Err.
    match tokio::try_join!(tcp_to_quic, quic_to_tcp) {
        Ok(((tcp_r, quic_w), (quic_r, tcp_w))) => {
            // Both tasks completed successfully.
            let bytes = (tcp_r, tcp_w, quic_r, quic_w);
            trace!(
                "Bidirectional copy for {} finished gracefully.",
                remote_addr
            );
            Ok(bytes)
        }
        Err(e) => {
            // One task failed, and the other was cancelled.
            // Byte counts are not accurate, so we report them as zero as requested.
            trace!(
                "Bidirectional copy for {} finished with an error: {:?}",
                remote_addr, e
            );
            let bytes = (0, 0, 0, 0);
            let proxy_error = match e {
                CopyError::Tcp(error) => ProxyError::TcpStreamError { error, bytes },
                CopyError::QuicRead(error) => ProxyError::QuicStreamReadError { error, bytes },
                CopyError::QuicWrite(error) => ProxyError::QuicStreamWriteError { error, bytes },
            };
            Err(proxy_error)
        }
    }
}

/// Handles a single incoming QUIC stream by echoing back all received data.
///
/// This function is designed to be a generic stream handler that can be spawned as a new task
/// for each accepted stream. It also manages an atomic counter to track the number of
/// active streams for a given connection.
///
/// ### Responsibilities
/// 1.  **Stream Counting**: It uses a RAII guard (`StreamCounterGuard`) to decrement a shared
///     `stream_count` when the function scope is exited, ensuring the count is always accurate
///     even if the stream processing fails.
/// 2.  **Echo Logic**: It reads all data from the `recv_stream`, logs the total amount, and
///     writes the exact same data back to the `send_stream`.
/// 3.  **Graceful Shutdown**: It properly closes the sending side of the stream (`send_stream.finish()`)
///     after echoing the data.
///
/// # Arguments
/// * `send_stream`: The stream for sending data back to the peer.
/// * `recv_stream`: The stream for receiving data from the peer.
/// * `stream_count`: An atomic counter shared by all streams of a single parent connection.
///
/// For provider
/// 1.  accept quic bi stream from server (and consumer behind the server)
/// 2.  wait 1 byte from quic stream
/// 3.  connect local TCP stream
/// 4.  copy local TCP stream and quic stream
///     no special treatment (if TCP stream down then drop QUIC stream, if QUIC stream down then drop TCP stream)
async fn handle_new_quic_stream_for_provider(
    mut send_stream: SendStream,
    mut recv_stream: RecvStream,
    _guard: StreamGuard,
    tcp_bind_address: String,
) {
    info!(
        "Handling a new server-initiated QUIC stream, proxying to local TCP: {}",
        tcp_bind_address
    );

    // First, wait for and read exactly one byte as a signal to proceed.
    let mut first_byte = [0u8; 1];
    match recv_stream.read_exact(&mut first_byte).await {
        Ok(()) => {
            info!(
                "Received signal byte ({}), proceeding to connect to local TCP service.",
                first_byte[0]
            );
        }
        Err(e) => {
            // Handle cases where the stream closes before even 1 byte is sent.
            if let ReadExactError::FinishedEarly(0) = e {
                info!("Stream closed before the signal byte was received.");
            } else {
                error!("Failed to read the signal byte from stream: {}", e);
            }
            return; // Exit if we can't get the signal byte.
        }
    }

    // 1. Connect to the local TCP service first.
    let mut tcp_stream = match TcpStream::connect(tcp_bind_address.clone()).await {
        Ok(stream) => {
            info!(
                "Successfully connected to local TCP service at {}",
                &tcp_bind_address
            );
            stream
        }
        Err(e) => {
            error!(
                "Failed to connect to local TCP service at {}: {}",
                tcp_bind_address, e
            );
            // Abruptly close the QUIC stream to signal failure to the server.
            let _ = send_stream.reset(1u32.into());
            return;
        }
    };

    // 2. After TCP connection is successful, send the signal byte to the local TCP service.
    if let Err(e) = tcp_stream.write_all(&first_byte).await {
        error!(
            "Failed to send signal byte to local TCP service {}: {}",
            tcp_bind_address, e
        );
        // Abruptly close the QUIC stream to signal failure to the server.
        let _ = send_stream.reset(2u32.into()); // Use a different error code to distinguish.
        return;
    }
    info!("Successfully sent signal byte to local TCP service.");

    // 3. Split the TCP stream and prepare for proxying.
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
    let local_tcp_addr = tcp_bind_address
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

    // 4. Start the bidirectional proxy.
    match copy_bidirectional_with_status(
        &mut tcp_read,
        &mut tcp_write,
        send_stream,
        recv_stream,
        local_tcp_addr,
    )
    .await
    {
        Ok((tcp_r, tcp_w, quic_r, quic_w)) => {
            info!(
                "Proxy for server-initiated stream to {} finished gracefully. Bytes (QUIC Read -> TCP Written): {} -> {}, (TCP Read -> QUIC Written): {} -> {}.",
                tcp_bind_address, quic_r, tcp_w, tcp_r, quic_w
            );
        }
        Err(e) => {
            error!(
                "Proxy for server-initiated stream to {} failed: {:?}",
                tcp_bind_address, e
            );
        }
    }
    info!(
        "Server-initiated stream handler finished for {}.",
        tcp_bind_address
    );
}

/// Trait for handling new incoming QUIC streams.
trait StreamHandler: Send + Sync + Clone + 'static {
    fn handle_stream(
        &self,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        guard: StreamGuard,
    ) -> impl Future<Output = ()> + Send;
}

/// Handler for Consumer clients (does nothing as they don't accept streams).
#[derive(Clone)]
struct ConsumerStreamHandler;
impl StreamHandler for ConsumerStreamHandler {
    fn handle_stream(
        &self,
        _send: quinn::SendStream,
        _recv: quinn::RecvStream,
        _guard: StreamGuard,
    ) -> impl Future<Output = ()> + Send {
        async move {
            warn!("Consumer received an unexpected server-initiated stream. Dropping it.");
            // guard is dropped here, decrementing count.
        }
    }
}

/// Handler for Provider clients (proxies streams to local TCP).
#[derive(Clone)]
struct ProviderStreamHandler {
    tcp_bind_address: String,
}
impl StreamHandler for ProviderStreamHandler {
    fn handle_stream(
        &self,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        guard: StreamGuard,
    ) -> impl Future<Output = ()> + Send {
        let addr = self.tcp_bind_address.clone();
        async move {
            tokio::spawn(handle_new_quic_stream_for_provider(send, recv, guard, addr));
        }
    }
}

/// Handler for Library usage (queues streams for the user).
#[derive(Clone)]
struct LibraryStreamHandler {
    queue: Arc<Mutex<VecDeque<(quinn::SendStream, quinn::RecvStream, StreamGuard)>>>,
    notify: Arc<Notify>,
    capacity: usize,
}
impl StreamHandler for LibraryStreamHandler {
    fn handle_stream(
        &self,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        guard: StreamGuard,
    ) -> impl Future<Output = ()> + Send {
        let queue = self.queue.clone();
        let notify = self.notify.clone();
        let capacity = self.capacity;
        async move {
            let mut q = queue.lock().await;
            if q.len() < capacity {
                q.push_back((send, recv, guard));
                notify.notify_one();
            } else {
                info!("Could not forward stream to application: queue is full. Stream will be dropped.");
                // guard is dropped here, decrementing count.
            }
        }
    }
}

/// Spawns a background task that periodically reconciles QUIC connections with DNS records.
fn spawn_connection_maintenance_task<S: StreamHandler>(
    server_name: String,
    server_port: u16,
    endpoint: quinn::Endpoint,
    stream_handler: S,
    hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
    endpoint_type: &'static str,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut maintenance_task_handles = HashMap::new();

        loop {
            interval.tick().await;
            HubConnectionManager::reconcile_to_dns(
                &server_name,
                server_port,
                &endpoint,
                stream_handler.clone(),
                &mut maintenance_task_handles,
                &hub_connections,
                endpoint_type,
            )
            .await;
        }
    })
}

/// Selects the best available QUIC connection based on a given strategy and opens a new stream.
/// This function contains the logic previously in `handle_new_tcp_connection`.
async fn open_stream_on_best_connection(
    hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
    strategy: ConnectionSelectionStrategy,
) -> Result<(SendStream, RecvStream, StreamGuard), Box<dyn Error + Send + Sync>> {
    // Wait for at least one connection to be available, with a timeout.
    const CONNECTION_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    let wait_start = Instant::now();

    loop {
        if !hub_connections.read().await.is_empty() {
            trace!("Connections are available, proceeding to open stream.");
            break;
        }
        if wait_start.elapsed() > CONNECTION_WAIT_TIMEOUT {
            warn!(
                "Timed out waiting for an active QUIC connection after {:?}.",
                CONNECTION_WAIT_TIMEOUT
            );
            return Err("Timed out waiting for an active QUIC connection.".into());
        }
        trace!("No connections available, waiting...");
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    let selected_connection = {
        let conns_guard = hub_connections.read().await;
        if conns_guard.is_empty() {
            info!("No active QUIC connections available to open a stream.");
            return Err("No active QUIC connections available".into());
        }

        let selected_info = match strategy {
            ConnectionSelectionStrategy::Oldest => {
                conns_guard.values()
                    .filter(|info| info.hub_status.load(Ordering::Relaxed) == HubStatus::Active as u8)
                    .min_by_key(|info| info.start_time)
            }
            ConnectionSelectionStrategy::Newest => {
                conns_guard.values()
                    .filter(|info| info.hub_status.load(Ordering::Relaxed) == HubStatus::Active as u8)
                    .max_by_key(|info| info.start_time)
            }
            ConnectionSelectionStrategy::Random => {
                let values: Vec<_> = conns_guard.values()
                    .filter(|info| info.hub_status.load(Ordering::Relaxed) == HubStatus::Active as u8)
                    .collect();
                values.choose(&mut rand::thread_rng()).copied()
            }
            ConnectionSelectionStrategy::LeastStreams => conns_guard
                .values()
                .filter(|info| info.hub_status.load(Ordering::Relaxed) == HubStatus::Active as u8)
                .min_by_key(|info| info.stream_count.load(Ordering::SeqCst)),
            ConnectionSelectionStrategy::LowestLatency => conns_guard
                .values()
                .filter(|info| info.hub_status.load(Ordering::Relaxed) == HubStatus::Active as u8)
                .min_by_key(|info| info.connection.rtt()),
        };

        if let Some(info) = selected_info {
            info!(
                "Selected connection with strategy {:?}: to {}, established at {:?}, duration: {:?}, rtt: {:?}",
                strategy,
                info.dest_addr,
                info.start_time,
                info.start_time.elapsed(),
                info.connection.rtt()
            );
            if !info.provider_start_sent.load(Ordering::Relaxed) {
                if let Err(e) = info.connection.send_datagram(b"request_provider_start".to_vec().into()) {
                    warn!("Failed to send start_provider datagram: {}", e);
                }
                info.provider_start_sent.store(true, Ordering::Relaxed);
            }
            Some((info.connection.clone(), info.stream_count.clone()))
        } else {
            None
        }
    };

    if let Some((connection, stream_count)) = selected_connection {
        // Note on Race Condition:
        // The connection status might transition to `ShuttingDown` (e.g., by another task handling
        // a shutdown signal) after we selected it above but before we open the stream here.
        // We prioritize code simplicity; it is acceptable to use a connection that is shutting down
        // if the timing difference is less than a second.
        info!("Attempting to open a bidirectional stream on the selected connection.");
        match connection.open_bi().await {
            Ok((send, recv)) => {
                stream_count.fetch_add(1, Ordering::Relaxed);
                let guard = StreamGuard { count: stream_count };
                info!("Successfully opened a bidirectional stream.");
                Ok((send, recv, guard))
            }
            Err(e) => {
                error!("Failed to open a stream on the selected connection: {}", e);
                Err(e.into())
            }
        }
    } else {
        Err(
            "Could not select a connection (this should not happen with active connections)."
                .into(),
        )
    }
}

/// Configuration for a client application instance.
/// This struct encapsulates all the parameters that differ between client binaries.
#[derive(Debug)]
pub struct AppConfig {
    /// Path to the client's certificate PEM file.
    pub cert_path: &'static str,
    /// Path to the client's private key PEM file.
    pub key_path: &'static str,
    /// Path to the trusted CA certificate(s) PEM file for server verification.
    pub trust_store_path: &'static str,
    /// A slice of supported ALPN protocols to advertise to the server.
    pub alpn: &'static [&'static [u8]],
    /// The local TCP address to listen on for control connections.
    /// **Note:** This is primarily used by the legacy `run_client` function.
    pub tcp_bind_address: &'static str,
    /// The DNS name of the server to connect to.
    pub server_name: &'static str,
    /// The port number of the server to connect to.
    pub server_port: u16,
}

/// Holds the state of a single QUIC connection to a Hub.
#[derive(Debug)]
struct HubConnection {
    /// The QUIC connection handle.
    pub connection: quinn::Connection,
    /// The destination address of the connection.
    pub dest_addr: SocketAddr,
    /// The time the connection was established.
    pub start_time: Instant,
    /// The number of active streams on this connection.
    pub stream_count: Arc<AtomicUsize>,
    /// Tracks activity statistics with internal mutability to avoid global write locks.
    pub activity_tracker: std::sync::Mutex<ActivityTracker>,
    /// The type of endpoint this connection belongs to (e.g., "provider", "consumer").
    pub endpoint_type: &'static str,
    /// Tracks if the provider start control message has been sent for this connection.
    pub provider_start_sent: AtomicBool,
    /// Tracks the perceived operational status of a peer Hub.
    pub hub_status: Arc<AtomicU8>,
    /// A signal to send a shutdown command to this connection's management task.
    pub shutdown_signal: Arc<Notify>,
    /// Tracks who initiated the shutdown (Hub or Endpoint).
    pub shutdown_initiator: Arc<AtomicU8>,
    /// The Common Name (CN) from the peer's certificate.
    pub peer_cn: Option<String>,
}

/// Mutable state for tracking connection activity.
#[derive(Debug)]
struct ActivityTracker {
    /// The last known statistics for this connection, used for idle detection.
    pub last_stats: quinn::ConnectionStats,
    /// The approximate time of the last detected data transfer on this connection.
    pub last_activity_time: Instant,
    /// A flag to prevent spamming idle warnings. True if a warning has already been logged.
    pub idle_warning_logged: bool,
}

/// Represents the perceived operational status of a peer Hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum HubStatus {
    /// The hub is active and can accept new endpoint streams.
    Active = 0,
    /// The hub is shutting down and will not accept new endpoint streams.
    ShuttingDown = 1,
    /// The hub has designated this connection as standby.
    StandBy = 2,
}

/// Represents who initiated the shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ShutdownInitiator {
    None = 0,
    Hub = 1,
    Endpoint = 2,
}

/// Namespace for functions that manage the collection of HubConnections.
struct HubConnectionManager;

impl HubConnectionManager {
    /// Performs a graceful shutdown of all active connections.
    ///
    /// This function signals all active connections to shut down and waits for them to complete
    /// or for a timeout to occur.
    async fn graceful_shutdown_all(
        hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
    ) {
        info!("Initiating graceful shutdown for all active connections...");
        let conns_guard = hub_connections.read().await;
        for info in conns_guard.values() {
            let prev_status = info.hub_status.swap(HubStatus::ShuttingDown as u8, Ordering::Relaxed);
            if prev_status != HubStatus::ShuttingDown as u8 {
                info.shutdown_initiator.store(ShutdownInitiator::Endpoint as u8, Ordering::Relaxed);
                info.shutdown_signal.notify_one();
            }
        }
        drop(conns_guard);

        let timeout = Duration::from_secs(60);
        let start = Instant::now();
        loop {
            if hub_connections.read().await.is_empty() {
                info!("All connections shut down gracefully.");
                break;
            }
            if start.elapsed() > timeout {
                let guard = hub_connections.read().await;
                warn!(
                    "Timeout waiting for connections to shut down. Remaining connections: {} (addrs: {:?})",
                    guard.len(),
                    guard.keys().collect::<Vec<_>>()
                );
                // Force close remaining connections upon timeout
                for info in guard.values() {
                    info.connection.close(0u32.into(), b"Shutdown Timeout");
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// A background task that periodically checks all active connections for data activity.
    async fn monitor_activity(
        hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
        check_interval: Duration,
        idle_threshold: Duration,
    ) {
        let mut interval = tokio::time::interval(check_interval);
        info!(
            "Starting connection activity monitor. Check interval: {:?}, Idle threshold: {:?}",
            check_interval, idle_threshold
        );

        loop {
            interval.tick().await;
            // Use read lock instead of write lock to allow concurrent stream creation
            let conns_guard = hub_connections.read().await;

            for (addr, info) in conns_guard.iter() {
                let current_stats = info.connection.stats();

                // Lock only the specific connection's tracker
                if let Ok(mut tracker) = info.activity_tracker.lock() {
                    // Check if any data has been sent or received since the last check.
                    if current_stats.udp_tx.bytes > tracker.last_stats.udp_tx.bytes
                        || current_stats.udp_rx.bytes > tracker.last_stats.udp_rx.bytes
                    {
                        // Activity detected, update the timestamp and reset the warning flag.
                        trace!("Activity detected on connection to {}", addr);
                        tracker.last_activity_time = Instant::now();
                        tracker.idle_warning_logged = false;
                    } else {
                        // No activity, check if the idle threshold has been exceeded.
                        let idle_duration = tracker.last_activity_time.elapsed();
                        if idle_duration > idle_threshold && !tracker.idle_warning_logged {
                            warn!(
                                "Connection to {} has been idle for approximately {:?}.",
                                addr, idle_duration
                            );
                            tracker.idle_warning_logged = true; // Log only once per idle period.
                        }
                    }
                    // Update the stats for the next comparison.
                    tracker.last_stats = current_stats;
                }
            }
        }
    }

    /// The central orchestrator for ensuring QUIC connections match DNS records.
    ///
    /// This function acts as a "reconciler". Its primary goal is to ensure that the
    /// application's actual state (the set of active `manage_single_quic_connection` tasks)
    /// matches the desired state (the set of IP addresses from the latest DNS query).
    async fn reconcile_to_dns<S: StreamHandler>(
        server_name: &str,
        server_port: u16,
        endpoint: &quinn::Endpoint,
        stream_handler: S,
        maintenance_task_handles: &mut HashMap<SocketAddr, tokio::task::JoinHandle<()>>,
        hub_connections: &Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
        endpoint_type: &'static str,
    ) {
        info!("Reconciling QUIC connections to DNS for '{}'", server_name);

        // Step 1: Define the "Desired State" by resolving the DNS name.
        let server_name_owned = server_name.to_string();
        let latest_addrs = match tokio::task::spawn_blocking(move || {
            (server_name_owned.as_str(), server_port).to_socket_addrs()
        })
        .await
        {
            Ok(Ok(addrs)) => addrs.collect::<HashSet<SocketAddr>>(),
            Ok(Err(e)) => {
                error!(
                    "DNS resolution failed for '{}': {}. Keeping existing connections.",
                    server_name, e
                );
                maintenance_task_handles.keys().cloned().collect()
            }
            Err(e) => {
                error!(
                    "DNS resolution task panicked: {}. Keeping existing connections.",
                    e
                );
                maintenance_task_handles.keys().cloned().collect()
            }
        };
        info!("Resolved '{}' to: {:?}", server_name, latest_addrs);

        // If DNS resolution was successful but returned an empty list, and we have active connections,
        // treat it as a temporary failure to prevent mass disconnection.
        if latest_addrs.is_empty() && !maintenance_task_handles.is_empty() {
            warn!(
                "DNS resolution for '{}' returned an empty list, but active connections exist. Assuming temporary failure and keeping existing connections.",
                server_name
            );
            return;
        }

        // 1. Identify IPs to be removed (no longer in DNS) and signal them to shut down.
        let mut to_remove = Vec::new();
        for addr in maintenance_task_handles.keys() {
            if !latest_addrs.contains(addr) {
                to_remove.push(*addr);
            }
        }

        if !to_remove.is_empty() {
            let conns_guard = hub_connections.read().await;
            for addr in to_remove {
                if let Some(info) = conns_guard.get(&addr) {
                    // Only send shutdown if it's currently active. Avoids sending multiple signals.
                    let prev_status = info.hub_status.swap(HubStatus::ShuttingDown as u8, Ordering::Relaxed);
                    if prev_status != HubStatus::ShuttingDown as u8 {
                        info!("Address {} is no longer in DNS records, initiating graceful shutdown.", addr);
                        info.shutdown_initiator.store(ShutdownInitiator::Endpoint as u8, Ordering::Relaxed);
                        info.shutdown_signal.notify_one();
                    }
                }
            }
        }

        // 2. Clean up any maintenance tasks that have fully completed (either by error or shutdown).
        maintenance_task_handles.retain(|addr, handle| {
            if handle.is_finished() {
                info!("Connection task for {} has finished. It will be removed.", addr);
                false
            } else {
                true
            }
        });

        // 2.5. Check for tasks that are in DNS but are ShuttingDown.
        // If found, remove them from maintenance_task_handles (detach them) so they are recreated in step 3.
        let conns_guard = hub_connections.read().await;
        let mut shutting_down_addrs = Vec::new();
        for addr in maintenance_task_handles.keys() {
            if latest_addrs.contains(addr) {
                if let Some(info) = conns_guard.get(addr) {
                    if info.hub_status.load(Ordering::Relaxed) == HubStatus::ShuttingDown as u8 {
                        shutting_down_addrs.push(*addr);
                    }
                }
            }
        }
        drop(conns_guard);

        for addr in shutting_down_addrs {
            info!("Connection to {} is shutting down but is in DNS. Detaching old task and starting a new one.", addr);
            maintenance_task_handles.remove(&addr); // Detach. The task continues to run/drain until finished.
        }

        // 3. Start new tasks for IPs that are in DNS but have no running task.
        let current_task_addrs: HashSet<_> = maintenance_task_handles.keys().cloned().collect();
        for addr_to_add in latest_addrs.difference(&current_task_addrs) {
            info!("New address {} found in DNS, starting a new connection manager task.", addr_to_add);
            let endpoint_clone = endpoint.clone();
            let server_name_clone = server_name.to_string();
            let stream_handler_clone = stream_handler.clone();
            let hub_connections_clone = hub_connections.clone();
            let handle = tokio::spawn(HubConnection::run(
                endpoint_clone,
                *addr_to_add,
                server_name_clone,
                stream_handler_clone,
                hub_connections_clone,
                endpoint_type,
            ));
            maintenance_task_handles.insert(*addr_to_add, handle);
        }

        info!(
            "Reconciliation complete. {} active QUIC connection tasks.",
            maintenance_task_handles.len(),
        );
    }
}

impl HubConnection {
    /// Helper to remove a connection from the map if the ID matches.
    async fn remove_from_map(
        hub_connections: &Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
        addr: SocketAddr,
        connection_id: usize,
    ) -> Option<HubConnection> {
        let mut guard = hub_connections.write().await;
        if let std::collections::hash_map::Entry::Occupied(entry) = guard.entry(addr) {
            if entry.get().connection.stable_id() == connection_id {
                return Some(entry.remove());
            }
        }
        None
    }

    /// Spawns a background task to handle incoming datagrams (control messages) for a connection.
    fn spawn_control_datagram_handler(
        connection: quinn::Connection,
        hub_status: Arc<AtomicU8>,
        shutdown_signal: Arc<Notify>,
        shutdown_initiator: Arc<AtomicU8>,
        addr: SocketAddr,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match connection.read_datagram().await {
                    Ok(bytes) => {
                        let msg = bytes.as_ref();
                        if msg == b"notify_shutdown" {
                            info!(
                                "Received notify_shutdown from Hub ({}). Marking connection as ShuttingDown.",
                                addr
                            );
                            hub_status.store(HubStatus::ShuttingDown as u8, Ordering::Relaxed);
                            shutdown_initiator.store(ShutdownInitiator::Hub as u8, Ordering::Relaxed);
                            // Trigger the main task's graceful shutdown logic via the shared channel.
                            shutdown_signal.notify_one();
                        } else if msg == b"notify_standby" {
                            info!(
                                "Received notify_standby from Hub ({}). Marking connection as StandBy.",
                                addr
                            );
                            hub_status.store(HubStatus::StandBy as u8, Ordering::Relaxed);
                        } else if msg == b"notify_active" {
                            info!(
                                "Received notify_active from Hub ({}). Marking connection as Active.",
                                addr
                            );
                            hub_status.store(HubStatus::Active as u8, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        // Connection closed or error, stop the handler.
                        break;
                    }
                }
            }
        })
    }

    /// Manages the entire lifecycle of a single QUIC connection in an autonomous task.
    ///
    /// This function is the "worker" spawned by the `reconcile_to_dns` "manager".
    /// It embodies a "self-registration and self-cleanup" pattern, making it highly autonomous.
    async fn run<S: StreamHandler>(
        endpoint: quinn::Endpoint,
        addr: SocketAddr,
        server_name: String,
        stream_handler: S,
        hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
        endpoint_type: &'static str,
    ) {
        let span = info_span!("HubConnection::run", remote_addr = %addr);
        let start_time_utc = Utc::now();
        async move {
            // --- 1. Connect ---
            info!("Attempting to establish QUIC connection...");
            let connection = match endpoint.connect(addr, &server_name) {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => {
                        info!("Connection handshake successful.");
                        conn
                    }
                    Err(e) => {
                        // Log the specific connection error. The reconciler will eventually try again.
                        error!("Connection failed during handshake: {}", e);
                        return; // End of this task.
                    }
                },
                Err(e) => {
                    error!("Failed to initiate connection: {}", e);
                    return; // End of this task
                }
            };

            // Extract certificate information for logging and ID compliance.
            let (peer_cn, _) = common::check_and_get_info_connection(connection.clone()).await;

            // --- 2. Register ---
            // This task is now responsible for this connection, so add it to the shared map.
            let stream_count = Arc::new(AtomicUsize::new(0));
            let hub_status = Arc::new(AtomicU8::new(HubStatus::Active as u8));
            let shutdown_signal = Arc::new(Notify::new());
            let shutdown_initiator = Arc::new(AtomicU8::new(ShutdownInitiator::None as u8));
            let connection_id = connection.stable_id();
            let cleanup_done = Arc::new(AtomicBool::new(false));

            // Start the datagram handler to listen for control messages (e.g., shutdown notifications).
            // This handles shutdown requests *initiated by the Hub*.
            let datagram_handler =
                Self::spawn_control_datagram_handler(connection.clone(), hub_status.clone(), shutdown_signal.clone(), shutdown_initiator.clone(), addr);

            let info = HubConnection {
                connection: connection.clone(),
                dest_addr: addr,
                start_time: Instant::now(),
                stream_count: stream_count.clone(),
                activity_tracker: std::sync::Mutex::new(ActivityTracker {
                    last_stats: connection.stats(),
                    last_activity_time: Instant::now(),
                    idle_warning_logged: false,
                }),
                endpoint_type,
                provider_start_sent: AtomicBool::new(false),
                hub_status: hub_status.clone(),
                shutdown_signal: shutdown_signal.clone(),
                shutdown_initiator: shutdown_initiator.clone(),
                peer_cn: peer_cn.clone(),
            };

            hub_connections.write().await.insert(addr, info);
            info!(
                message = "QUIC connection started",
                startAt = %start_time_utc.to_rfc3339(),
                quic_connection_id = %connection_id,
                spnEndPoint = ?peer_cn,
                endpoint_type = endpoint_type,
                server_ip = %addr,
            );

            // RAII Guard to ensure cleanup if the task is aborted (e.g. by DNS reconciliation).
            struct HubConnectionCleanupGuard {
                addr: SocketAddr,
                connection_id: usize,
                hub_connections: Arc<RwLock<HashMap<SocketAddr, HubConnection>>>,
                start_time_utc: chrono::DateTime<Utc>,
                datagram_handler: JoinHandle<()>,
                cleanup_done: Arc<AtomicBool>,
            }
            impl Drop for HubConnectionCleanupGuard {
                fn drop(&mut self) {
                    self.datagram_handler.abort();
                    if self.cleanup_done.load(Ordering::Relaxed) {
                        return;
                    }
                    let addr = self.addr;
                    let connection_id = self.connection_id;
                    let hub_connections = self.hub_connections.clone();
                    let start_time_utc = self.start_time_utc;
                    tokio::spawn(async move {
                        // This runs only when the task is aborted (e.g. DNS change), ensuring cleanup.
                        if let Some(removed_info) = HubConnection::remove_from_map(&hub_connections, addr, connection_id).await {
                            info!(
                                message = "QUIC connection task aborted",
                                startAt = %start_time_utc.to_rfc3339(),
                                    quic_connection_id = %removed_info.connection.stable_id(),
                                    spnEndPoint = ?removed_info.peer_cn,
                                    endpoint_type = removed_info.endpoint_type,
                                    server_ip = %removed_info.dest_addr,
                                    duration_secs = removed_info.start_time.elapsed().as_secs_f64(),
                                    reason = "Task Aborted",
                                    terminateReason = "shutdown",
                                    total_quic_streams = removed_info.stream_count.load(Ordering::Relaxed),
                            );
                            // Ensure the connection is closed
                            removed_info.connection.close(0u32.into(), b"Task Aborted");
                        }
                    });
                }
            }
            let _guard = HubConnectionCleanupGuard {
                addr,
                connection_id,
                hub_connections: hub_connections.clone(),
                start_time_utc,
                datagram_handler,
                cleanup_done: cleanup_done.clone(),
            };

            // --- 3. Work (Accept Streams) & Monitor (Watch for Close) ---
            let reason = tokio::select! {
                // Branch A: Connection closes unexpectedly (by peer or network error).
                reason = connection.closed() => {
                    info!("Connection to {} closed by peer or due to error.", addr);
                    reason
                },

                // Branch B: Graceful shutdown is requested by us (via DNS change or signal).
                _ = shutdown_signal.notified() => {
                    let initiator_val = shutdown_initiator.load(Ordering::Relaxed);
                    let initiator_str = match initiator_val {
                        1 => "Hub instruction",
                        2 => "Endpoint termination",
                        _ => "Unknown",
                    };
                    info!("Graceful shutdown triggered by {} for connection to {}. Draining...", initiator_str, addr);

                    // The caller should have already set the status, but we ensure it.
                    hub_status.store(HubStatus::ShuttingDown as u8, Ordering::Relaxed);

                    // Notify the peer hub to stop sending new streams.
                    connection.set_max_concurrent_bi_streams(0u32.into());

                    // Send notify_shutdown datagram
                    if let Err(e) = connection.send_datagram(b"notify_shutdown".to_vec().into()) {
                        warn!("Failed to send notify_shutdown datagram to {}: {}", addr, e);
                    }

                    // Wait for active streams to drain or for a timeout.
                    let timeout = common::GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT;
                    let start = Instant::now();
                    let mut forced = false;
                    loop {
                        let count = stream_count.load(Ordering::Relaxed);
                        if count == 0 {
                            info!("Connection {} drained successfully.", addr);
                            break;
                        }
                        if start.elapsed() > timeout {
                            warn!("Connection {} drain timed out with {} active streams. Forcing close.", addr, count);
                            forced = true;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }

                    // Close the connection from our side.
                    let reason_bytes = if forced {
                        b"Graceful Shutdown: Forced by Timeout".as_slice()
                    } else {
                        b"Graceful Shutdown: Completed".as_slice()
                    };
                    connection.close(0u32.into(), reason_bytes);

                    // Wait for the connection to fully close and get the final reason.
                    connection.closed().await
                },


                // Branch C: Normal work (accepting server-initiated streams).
                _ = async {
                    loop {
                        match connection.accept_bi().await {
                            Ok(streams) => {
                                stream_count.fetch_add(1, Ordering::Relaxed);
                            let guard = StreamGuard { count: stream_count.clone() };
                                trace!("Accepted a new bidirectional stream. Active streams: {}", stream_count.load(Ordering::Relaxed));
                            stream_handler.handle_stream(streams.0, streams.1, guard).await;
                            }
                            Err(e) => {
                                // This error typically occurs when the connection is closing.
                                trace!("Stream listener for {} is stopping: {}", addr, e);
                                break;
                            }
                        }
                    }
                } => {
                    // The stream acceptance loop broke. We assume the connection is closing and wait for the official reason.
                    connection.closed().await
                }
            };

            // --- 4. Cleanup ---
            // The connection has closed. This task's final responsibility is to remove itself from the shared map.
            let removed_info = HubConnection::remove_from_map(&hub_connections, addr, connection_id).await;
            cleanup_done.store(true, Ordering::Relaxed);

            if let Some(removed_info) = removed_info {
                let terminate_reason = match &reason {
                    quinn::ConnectionError::LocallyClosed => "shutdown",
                    quinn::ConnectionError::ConnectionClosed(_)
                    | quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::Reset => "terminatedByPeer",
                    quinn::ConnectionError::VersionMismatch
                    | quinn::ConnectionError::TransportError(_)
                    | quinn::ConnectionError::TimedOut
                    | quinn::ConnectionError::CidsExhausted => "error",
                };

                info!(
                    message = "QUIC connection ended",
                    startAt = %start_time_utc.to_rfc3339(),
                    quic_connection_id = %removed_info.connection.stable_id(),
                    spnEndPoint = ?removed_info.peer_cn,
                    endpoint_type = removed_info.endpoint_type,
                    server_ip = %removed_info.dest_addr,
                    duration_secs = removed_info.start_time.elapsed().as_secs_f64(),
                    reason = %reason,
                    terminateReason = terminate_reason,
                    total_quic_streams = removed_info.stream_count.load(Ordering::Relaxed),
                );
            } else {
                // This case is unlikely but possible if another part of the system (e.g., a forceful shutdown)
                // clears the map.
                warn!("Connection info for {} was already removed during cleanup.", addr);
            }

            // --- 5. Terminate ---
            // The task's work is done.
            info!("Task finished.");
        }
        .instrument(span)
        .await
    }
}

/// Defines the strategy for selecting a connection from the pool.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum ConnectionSelectionStrategy {
    Oldest,
    Newest,
    Random,
    LeastStreams,
    LowestLatency,
}

/// Configuration for the TCP-to-QUIC proxy retry mechanism.
#[derive(Debug, Clone, Copy)]
pub struct ProxyRetryConfig {
    /// Maximum number of times to retry opening a QUIC stream after a disconnection.
    pub max_retries: u32,
    /// The delay to wait before attempting a retry.
    pub retry_delay: Duration,
    /// The total maximum time allowed for the entire proxy session, including all retries.
    pub total_timeout: Duration,
}

impl Default for ProxyRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(2),
            total_timeout: Duration::from_secs(30),
        }
    }
}

/// Distinguishes between errors originating from the TCP stream versus the QUIC stream,
/// and carries the byte counts at the time of error.
#[derive(Debug)]
enum ProxyError {
    /// An error occurred on the QUIC stream during a read operation.
    QuicStreamReadError {
        error: quinn::ReadError,
        /// A tuple containing bytes transferred: (tcp_read, tcp_written, quic_read, quic_written)
        bytes: (u64, u64, u64, u64),
    },
    /// An error occurred on the QUIC stream during a write operation.
    QuicStreamWriteError {
        error: quinn::WriteError,
        /// A tuple containing bytes transferred: (tcp_read, tcp_written, quic_read, quic_written)
        bytes: (u64, u64, u64, u64),
    },
    /// An error occurred on the local TCP stream, which is generally non-recoverable.
    TcpStreamError {
        error: std::io::Error,
        /// A tuple containing bytes transferred: (tcp_read, tcp_written, quic_read, quic_written)
        bytes: (u64, u64, u64, u64),
    },
}
