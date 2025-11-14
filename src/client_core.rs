//! # Client Core Logic & Library API
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
//!             Ok((_send, _recv)) => {
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
//! let (mut send_stream, _recv_stream) = provider.open_stream().await?;
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
//! - The `create_spn_endpoint` function contains a hardcoded "provider" string that should be removed or made configurable.
//! - Investigate using DashMap for the connection pool.
//! - Check if the number of Tokio tasks in the consumer crate is decreasing too slowly.
//! - The use of `Box::leak(host_slice.to_string().into_boxed_str())` is awkward; look for a cleaner alternative.
//!
//! # Considerations
//! For copying data between two streams, we evaluated `tokio::io::copy_bidirectional` against
//! a custom implementation using `tokio::select!`, `join!`, or `try_join!`. The decision
//! is based on a trade-off between robustness, counter accuracy, error detail, performance,
//! and code simplicity.

use std::error::Error;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::time::Duration;
use quinn::{ReadExactError, RecvStream, SendStream};
use std::net::ToSocketAddrs;
use tracing::Instrument;
use tracing::info_span;
use tracing::{error, info, trace, warn};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::task::JoinHandle;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use futures::future;
use rand::seq::SliceRandom;
use chrono::Utc;

use crate::common;
use crate::common::create_quic_client_endpoint;

//======================================================================
//== Public Library API
//======================================================================

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
    /// Shared dictionary of active QUIC connections.
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
    /// Handle to the main background maintenance task.
    maintenance_task: JoinHandle<()>,
    /// Handle to the background activity monitoring task.
    activity_monitor_task: JoinHandle<()>,
    /// Sender for a shutdown signal to gracefully stop other background tasks.
    shutdown_tx: broadcast::Sender<()>,
    /// Receiver for server-initiated streams, ready to be accepted by the user.
    accepted_stream_rx: Mutex<mpsc::Receiver<(SendStream, RecvStream)>>,
}

impl Drop for SpnEndpoint {
    fn drop(&mut self) {
        info!("SpnEndpoint is being dropped, initiating shutdown.");
        // This automatic cleanup via RAII is functionally equivalent to the manual
        // shutdown process at the end of the `run_client` function.

        // Signal all tasks listening on the shutdown channel.
        // This causes the main maintenance loop to stop gracefully, which in turn
        // aborts the individual connection maintenance tasks (`maintain_quic_connection`).
        // This is equivalent to the loop over `maintenance_task_handles` in `run_client`.
        let _ = self.shutdown_tx.send(());

        // Abort the main maintenance task itself as a final measure.
        // The cleanup process after this task's loop also executes `endpoint.close()`.
        self.maintenance_task.abort();

        // Abort the activity monitor task.
        // This is directly equivalent to `activity_monitor_task.abort()` in `run_client`.
        self.activity_monitor_task.abort();
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
    /// A `Result` containing a tuple of `(SendStream, RecvStream)` on success.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream), Box<dyn Error>> {
        let mut rx = self.accepted_stream_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| "Provider has been shut down.".into())
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
    /// A `Result` containing a tuple of `(SendStream, RecvStream)` on success.
    pub async fn open_stream(
        &self,
    ) -> Result<(SendStream, RecvStream), Box<dyn Error + Send + Sync>> {
        info!("Requesting a new QUIC stream from the provider.");
        let stream = open_stream_on_best_connection(
            self.connections.clone(),
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
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, ConnectionInfo>::new()));
    //let (conn_tx, conn_rx) = mpsc::channel::<(quinn::Connection, &'static str)>(128);
    let (stream_tx, stream_rx) =
        mpsc::channel::<(quinn::SendStream, quinn::RecvStream, Arc<AtomicUsize>)>(1024);
    // Channel for streams accepted from the server, to be passed to the library user.
    let (accepted_stream_tx, accepted_stream_rx) = mpsc::channel::<(SendStream, RecvStream)>(128);

    let (shutdown_tx, _) = broadcast::channel(1);

    // Start the activity monitor task. This task will run in the background.
    let monitor_connections = connections.clone();
    let activity_monitor_task = tokio::spawn(monitor_approx_connection_activity(
        monitor_connections,
        // Check for activity every 10 seconds.
        Duration::from_secs(10),
        // Log a warning if a connection is idle for more than 30 seconds.
        Duration::from_secs(30),
    ));

    // Clone variables to be moved into the maintenance task.
    let maintenance_connections = connections.clone();
    let maintenance_shutdown_tx = shutdown_tx.clone();
    let server_name_owned = server_name.to_string();

    let maintenance_task = tokio::spawn(async move {
        // The logic from `run_maintenance_loop` is now inlined here.
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut maintenance_task_handles =
            HashMap::<SocketAddr, tokio::task::JoinHandle<()>>::new();
        let mut shutdown_rx = maintenance_shutdown_tx.subscribe();
        //let mut conn_rx = conn_rx;
        let mut stream_rx = stream_rx;

        info!("Connection maintenance loop started.");

        loop {
            tokio::select! {
                // Branch 1: Handle shutdown signal from the SpnEndpoint's Drop impl.
                _ = shutdown_rx.recv() => {
                    info!("Maintenance loop received shutdown signal. Exiting.");
                    for (addr, handle) in maintenance_task_handles {
                        info!("Aborting connection manager task for {}", addr);
                        handle.abort();
                    }
                    break;
                },
                // Branch 2: Handle periodic DNS check and task management.
                _ = interval.tick() => {
                    // Spawn the check as a background task to avoid blocking the main loop.
                    reconcile_quic_connections_to_dns(
                        &server_name_owned,
                        server_port,
                        &endpoint,
                        &stream_tx,
                        &mut maintenance_task_handles,
                        &maintenance_connections,
                        "provider",
                    ).await;
                    /*
                    tokio::spawn(handle_periodic_dns_check(
                        server_name_owned.clone(),
                        server_port,
                        endpoint.clone(),
                        conn_tx.clone(),
                        maintenance_task_handles.clone(),
                        maintenance_connections.clone(),
                        "provider",
                    ));
                    */
                },

                // Branch 3: Handle a new QUIC connection established by a sub-task.
                /* This function is deprecated. An AI-assisted review found the event-driven approach to be unsuitable here.
                Some((quic_connection, endpoint_type)) = conn_rx.recv() => {
                    // Spawn as a background task to avoid blocking.
                    tokio::spawn(handle_new_quic_connection(
                        quic_connection,
                        stream_tx.clone(),
                        Arc::clone(&maintenance_connections),
                        endpoint_type,
                    ));
                },
             */
                // Branch 4: Handle a new server-initiated QUIC stream.
                Some((send_stream, recv_stream, _stream_count)) = stream_rx.recv() => {
                    info!("Received a new server-initiated QUIC stream (library mode).");
                    // Try to send the stream to the user via the `connected_stream` method.
                    match accepted_stream_tx.try_send((send_stream, recv_stream)) {
                        Ok(()) => {
                            info!("Forwarded stream to the application via connected_stream.");
                        }
                        Err(TrySendError::Full(_)) => {
                            // The user is not calling `connected_stream` fast enough, or not at all.
                            // Per the request, do not fall back. Just log and drop the stream.
                            info!("Could not forward stream to application: channel is full. Stream will be dropped.");
                        }
                        Err(TrySendError::Closed(_)) => {
                            // The SpnEndpoint has been dropped, so the receiver is gone.
                            info!("Cannot forward server-initiated stream, user receiver is closed. Shutting down loop.");
                            break;
                        }
                    }
                },
            }
        }

        info!("Maintenance loop finished. Closing endpoint.");
        endpoint.close(0u32.into(), b"shutting down");
        endpoint.wait_idle().await;
        info!("Endpoint shutdown complete.");
    });

    Ok(SpnEndpoint {
        connections,
        maintenance_task,
        activity_monitor_task,
        shutdown_tx,
        accepted_stream_rx: Mutex::new(accepted_stream_rx),
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
    info!(
        "Consumer Client started with config for: {}, {}, {}, {}, {}, {}",
        server_name, server_port, trust_store_path, cert_path, key_path, tcp_bind_address
    );
    common::initialize_crypto_provider();

    let (cert_path, key_path, trust_store_path) =
        common::load_certs_and_key(cert_path, key_path, trust_store_path)?;

    let endpoint =
        create_quic_client_endpoint(cert_path, key_path, trust_store_path, &[b"sc01-consumer"])?;

    // Dictionary to store active quic connections and their info, accessible from multiple tasks.
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, ConnectionInfo>::new()));

    // Start the activity monitor task. This task will run in the background.
    let monitor_connections = connections.clone();
    let activity_monitor_task = tokio::spawn(monitor_approx_connection_activity(
        monitor_connections,
        // Check for activity every 10 seconds.
        Duration::from_secs(10),
        // Log a warning if a connection is idle for more than 30 seconds.
        Duration::from_secs(30),
    ));

    // Channel to receive newly established quic connections from handler tasks.
    //let (conn_tx, mut conn_rx) = mpsc::channel::<(quinn::Connection, &'static str)>(128);

    // Channel to receive incoming streams from any connection to be handled by the main loop.
    let (stream_tx, _stream_rx) =
        mpsc::channel::<(quinn::SendStream, quinn::RecvStream, Arc<AtomicUsize>)>(1024);

    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut maintenance_task_handles = HashMap::<SocketAddr, tokio::task::JoinHandle<()>>::new();

    // Defines the graceful shutdown level. 0=none, 1=forceful(SIGQUIT), 2=gentle(SIGINT/SIGTERM).
    let shutdown_graceful_level;

    // A vector to keep track of spawned TCP proxy tasks.
    let mut proxy_task_handles: Vec<JoinHandle<()>> = Vec::new();

    // Bind a TCP listener for local control.
    let listener = TcpListener::bind(tcp_bind_address).await?;
    info!(
        "Listening for local TCP control connections on {}",
        tcp_bind_address
    );

    // --- Robust Signal Handling Setup ---
    // Use a watch channel to broadcast the shutdown signal. This is more robust than
    // placing signal handlers directly in the main select! loop, as it decouples
    // signal handling from the main loop's processing.
    // 0: no shutdown, 1: forceful, 2: gentle
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(0u8);

    // Spawn a dedicated task for handling OS signals.
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
            .expect("Failed to install SIGQUIT handler");

        info!("SIGNAL PROCESS START!");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C (SIGINT) received, sending gentle shutdown signal.");
                // On error, the receiver has been dropped, so the program is shutting down anyway.
                let _ = shutdown_tx.send(2);
            },
            _ = sigterm.recv() => {
                info!("SIGTERM received, sending gentle shutdown signal.");
                let _ = shutdown_tx.send(2);
            },
            _ = sigquit.recv() => {
                info!("Ctrl-\\ (SIGQUIT) received, sending forceful shutdown signal.");
                let _ = shutdown_tx.send(1);
            },
        }
    });

    // Main event loop
    'main_loop: loop {
        tokio::select! {
            // Branch 1: Handle periodic DNS check and task management.
            _ = interval.tick() => {
                // Spawn the check as a background task to avoid blocking the main loop.
                reconcile_quic_connections_to_dns(
                    server_name,
                    server_port,
                    &endpoint,
                    &stream_tx,
                    &mut maintenance_task_handles,
                    &connections,
                    "consumer",
                ).await;
            },

            // Branch 2: Handle a new QUIC connection.
            /* event driven was deleted by AI
            Some((quic_connection, endpoint_type)) = conn_rx.recv() => {
                tokio::spawn(handle_new_quic_connection(
                    quic_connection,
                    stream_tx.clone(),
                    Arc::clone(&connections),
                    endpoint_type,
                ));
            },
            */

            // Branch 3: Handle a new QUIC stream from any connection.
            //   * consumer does not listen QUIC stream
            //Some((send_stream, recv_stream, stream_count)) = stream_rx.recv() => {
            //    info!("Received a new QUIC stream in main loop. Spawning handler.");
            //    tokio::spawn(handle_new_quic_stream(
            //        send_stream,
            //        recv_stream,
            //        stream_count,
            //        tcp_bind_address.to_string(),
            //    ));
            //},

            // Branch 4: Handle a new TCP connection for control/query.
            Ok((tcp_stream, remote_addr)) = listener.accept() => {
                info!("Accepted TCP connection from: {}", remote_addr);
                let connections_clone = Arc::clone(&connections);
                let strategy = ConnectionSelectionStrategy::LowestLatency;
                let retry_config = ProxyRetryConfig::default();
                let handle = tokio::spawn(
                    handle_new_tcp_connection(tcp_stream, remote_addr, connections_clone, strategy, retry_config)
                    .instrument(info_span!("quic/tcp proxy session", client_addr = %remote_addr))
                );
                proxy_task_handles.push(handle);
            },

            // Branch 5: Handle shutdown signal from the dedicated signal handling task.
            _ = shutdown_rx.changed() => {
                let level = *shutdown_rx.borrow();
                if level > 0 {
                    info!("Shutdown signal (level {}) received via channel, breaking main loop.", level);
                    shutdown_graceful_level = level;
                    break 'main_loop;
                }
            },
        }
    }

    // --- Graceful Shutdown ---
    // Execute shutdown procedures based on the graceful level.
    // Higher levels include the procedures of all lower levels.

    info!("Shutting down {}", shutdown_graceful_level);

    if shutdown_graceful_level >= 2 {
        // --- Level 2 Shutdown (Most Gentle: SIGINT/SIGTERM) ---
        info!("Executing level 2 shutdown: Gracefully closing streams...");

        // 1-1. Stop accepting new local TCP connections immediately.
        // Existing TCP proxy tasks will continue to run.
        info!("Stopping local TCP listener to prevent new connections...");
        drop(listener);

        // 1-2. Wait for all active TCP proxy tasks to complete, with a 1-minute timeout.
        info!("Waiting for active TCP proxy tasks to finish (up to 1 minute)...");
        if !proxy_task_handles.is_empty() {
            let proxy_tasks_future = future::join_all(proxy_task_handles);
            match tokio::time::timeout(Duration::from_secs(60), proxy_tasks_future).await {
                Ok(results) => {
                    let failed_tasks = results.into_iter().filter(|res| res.is_err()).count();
                    if failed_tasks > 0 {
                        warn!("{} TCP proxy tasks failed during shutdown.", failed_tasks);
                    } else {
                        info!("All active TCP proxy tasks finished gracefully.");
                    }
                }
                Err(_) => {
                    warn!(
                        "Timeout reached while waiting for TCP proxy tasks to finish. Proceeding with forceful shutdown."
                    );
                }
            }
        }

        // 2-1. Prevent new server-initiated QUIC streams by setting MAX_STREAMS to 0.
        //    This allows existing streams to finish their work.
        info!("Notifying all peers to stop opening new streams...");
        let conns_guard = connections.read().await;
        for info in conns_guard.values() {
            info.connection.set_max_concurrent_bi_streams(0u32.into());
        }
        drop(conns_guard); // Release the read lock before waiting.

        // 2-2. Wait for all existing QUIC streams to finish, with a 1-minute timeout.
        info!("Waiting for active streams to finish (up to 1 minute)...");
        match tokio::time::timeout(Duration::from_secs(60), endpoint.wait_idle()).await {
            Ok(()) => {
                info!("All active quic streams finished gracefully.");
            }
            Err(_) => {
                warn!(
                    "Timeout reached while waiting for streams to finish. Proceeding with forceful shutdown."
                );
                // If timeout occurs, we'll fall through to the level 1 shutdown,
                // which will close the endpoint forcefully.
            }
        }
    }

    if shutdown_graceful_level >= 1 {
        // --- Level 1 Shutdown (Base: SIGQUIT and above) ---
        // This is the base shutdown procedure that is always executed on a signal.
        info!("Executing base level 1 shutdown tasks...");
        info!("Aborting activity monitor task.");
        activity_monitor_task.abort();

        for (addr, handle) in maintenance_task_handles {
            info!("Aborting connection manager task for {}", addr);
            handle.abort();
        }

        // Close the endpoint immediately. This will terminate any remaining connections
        // that did not close gracefully.
        endpoint.close(0u32.into(), b"shutting down");
        // We still wait for the endpoint to become idle to ensure resources are released.
        endpoint.wait_idle().await;
        info!("Shutdown complete.");
    } else {
        // This case should ideally not be reached.
        warn!("Shutdown initiated without a recognized signal.");
    }

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
    info!(
        "Provider Client started with config for: {}, {}, {}, {}, {}, {}",
        server_name, server_port, trust_store_path, cert_path, key_path, tcp_bind_address
    );
    common::initialize_crypto_provider();

    let (cert_path, key_path, trust_store_path) =
        common::load_certs_and_key(cert_path, key_path, trust_store_path)?;

    let endpoint =
        create_quic_client_endpoint(cert_path, key_path, trust_store_path, &[b"sc01-provider"])?;

    // Dictionary to store active quic connections and their info, accessible from multiple tasks.
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, ConnectionInfo>::new()));

    // Start the activity monitor task. This task will run in the background.
    let monitor_connections = connections.clone();
    let activity_monitor_task = tokio::spawn(monitor_approx_connection_activity(
        monitor_connections,
        // Check for activity every 10 seconds.
        Duration::from_secs(10),
        // Log a warning if a connection is idle for more than 30 seconds.
        Duration::from_secs(30),
    ));

    // Channel to receive newly established quic connections from handler tasks.
    //let (conn_tx, mut conn_rx) = mpsc::channel::<(quinn::Connection, &'static str)>(128);

    // Channel to receive incoming streams from any connection to be handled by the main loop.
    let (stream_tx, mut stream_rx) =
        mpsc::channel::<(quinn::SendStream, quinn::RecvStream, Arc<AtomicUsize>)>(1024);

    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut maintenance_task_handles = HashMap::<SocketAddr, tokio::task::JoinHandle<()>>::new();

    // --- Robust Signal Handling Setup ---
    // Use a watch channel to broadcast the shutdown signal. This is more robust than
    // placing signal handlers directly in the main select! loop, as it decouples
    // signal handling from the main loop's processing.
    // 0: no shutdown, 1: forceful, 2: gentle
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(0u8);

    // Spawn a dedicated task for handling OS signals.
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
            .expect("Failed to install SIGQUIT handler");

        info!("SIGNAL PROCESS START!");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C (SIGINT) received, sending gentle shutdown signal.");
                // On error, the receiver has been dropped, so the program is shutting down anyway.
                let _ = shutdown_tx.send(2);
            },
            _ = sigterm.recv() => {
                info!("SIGTERM received, sending gentle shutdown signal.");
                let _ = shutdown_tx.send(2);
            },
            _ = sigquit.recv() => {
                info!("Ctrl-\\ (SIGQUIT) received, sending forceful shutdown signal.");
                let _ = shutdown_tx.send(1);
            },
        }
    });

    // Defines the graceful shutdown level. 0=none, 1=forceful(SIGQUIT), 2=gentle(SIGINT/SIGTERM).
    let shutdown_graceful_level;

    // A vector to keep track of spawned TCP proxy tasks.
    //let mut proxy_task_handles: Vec<JoinHandle<()>> = Vec::new();
    //
    // Bind a TCP listener for local control.
    //let listener = TcpListener::bind(tcp_bind_address).await?;
    //info!(
    //    "Listening for local TCP control connections on {}",
    //    tcp_bind_address
    //);

    // Main event loop
    'main_loop: loop {
        tokio::select! {
            // Branch 1: Handle periodic DNS check and task management.
            _ = interval.tick() => {
                // Spawn the check as a background task to avoid blocking the main loop.
                reconcile_quic_connections_to_dns(
                    server_name,
                    server_port,
                    &endpoint,
                    &stream_tx,
                    &mut maintenance_task_handles,
                    &connections,
                    "provider",
                ).await;
            },

            // Branch 2: Handle a new QUIC connection.
            /* event driven was deleted by AI
            Some((quic_connection, endpoint_type)) = conn_rx.recv() => {
                handle_new_quic_connection(
                    quic_connection,
                    stream_tx.clone(),
                    Arc::clone(&connections),
                    endpoint_type,
                )
                .await;
            },
            */

            // Branch 3: Handle a new QUIC stream from any connection.
            Some((send_stream, recv_stream, stream_count)) = stream_rx.recv() => {
                info!("Received a new QUIC stream in main loop. Spawning handler.");
                tokio::spawn(handle_new_quic_stream_for_provider(
                    send_stream,
                    recv_stream,
                    stream_count,
                    tcp_bind_address.to_string(),
                ));
            },

            // Branch 4: Handle a new TCP connection for control/query.
            //  provider does not listen local TCP
            //Ok((tcp_stream, remote_addr)) = listener.accept() => {
            //    info!("Accepted TCP control connection from: {}", remote_addr);
            //    let connections_clone = Arc::clone(&connections);
            //    let strategy = ConnectionSelectionStrategy::LowestLatency;
            //    let retry_config = ProxyRetryConfig::default();
            //    let handle = tokio::spawn(handle_new_tcp_connection(tcp_stream, remote_addr, connections_clone, strategy, retry_config));
            //         proxy_task_handles.push(handle);
            //},

            // Branch 5: Handle shutdown signal from the dedicated signal handling task.
            _ = shutdown_rx.changed() => {
                let level = *shutdown_rx.borrow();
                if level > 0 {
                    info!("Shutdown signal (level {}) received via channel, breaking main loop.", level);
                    shutdown_graceful_level = level;
                    break 'main_loop;
                }
            },
        }
    }

    // --- Graceful Shutdown ---
    // Execute shutdown procedures based on the graceful level.
    // Higher levels include the procedures of all lower levels.

    if shutdown_graceful_level >= 2 {
        // --- Level 2 Shutdown (Most Gentle: SIGINT/SIGTERM) ---
        info!("Executing level 2 shutdown: Gracefully closing streams...");

        // 2-1. Prevent new server-initiated QUIC streams by setting MAX_STREAMS to 0.
        //    This allows existing streams to finish their work.
        info!("Notifying all peers to stop opening new streams...");
        let conns_guard = connections.read().await;
        for info in conns_guard.values() {
            info.connection.set_max_concurrent_bi_streams(0u32.into());
        }
        drop(conns_guard); // Release the read lock before waiting.

        // 2-2. Wait for all existing QUIC streams to finish, with a 1-minute timeout.
        info!("Waiting for active streams to finish (up to 1 minute)...");
        match tokio::time::timeout(Duration::from_secs(60), endpoint.wait_idle()).await {
            Ok(()) => {
                info!("All active quic streams finished gracefully.");
            }
            Err(_) => {
                warn!(
                    "Timeout reached while waiting for streams to finish. Proceeding with forceful shutdown."
                );
                // If timeout occurs, we'll fall through to the level 1 shutdown,
                // which will close the endpoint forcefully.
            }
        }
    }

    info!("Shutting down {}", shutdown_graceful_level);

    if shutdown_graceful_level >= 1 {
        // --- Level 1 Shutdown (Base: SIGQUIT and above) ---
        // This is the base shutdown procedure that is always executed on a signal.
        info!("Executing base level 1 shutdown tasks...");
        info!("Aborting activity monitor task.");
        activity_monitor_task.abort();

        for (addr, handle) in maintenance_task_handles {
            info!("Aborting connection manager task for {}", addr);
            handle.abort();
        }

        // Close the endpoint immediately. This will terminate any remaining connections
        // that did not close gracefully.
        endpoint.close(0u32.into(), b"shutting down");
        // We still wait for the endpoint to become idle to ensure resources are released.
        endpoint.wait_idle().await;
        info!("Shutdown complete.");
    } else {
        // This case should ideally not be reached.
        warn!("Shutdown initiated without a recognized signal.");
    }

    // Add a small delay to allow background tasks to finish logging before the main process exits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

//======================================================================
//== Internal Helper Functions
//======================================================================

/// A background task that periodically checks all active connections for data activity.
///
/// This function implements the "periodic polling" approach. It does not interfere with
/// the data path, making it very low-impact. It wakes up at a regular interval,
/// checks the `quinn::ConnectionStats` for each connection, and updates an
/// "last activity" timestamp if any data has been transferred.
///
/// # Arguments
/// * `connections`: A shared reference to the map of active connections.
/// * `check_interval`: How often to poll for activity.
/// * `idle_threshold`: The duration after which a connection is considered idle, triggering a log message.
async fn monitor_approx_connection_activity(
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
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
        let mut conns_guard = connections.write().await;

        for (addr, info) in conns_guard.iter_mut() {
            let current_stats = info.connection.stats();

            // Check if any data has been sent or received since the last check.
            if current_stats.udp_tx.bytes > info.last_stats.udp_tx.bytes
                || current_stats.udp_rx.bytes > info.last_stats.udp_rx.bytes
            {
                // Activity detected, update the timestamp and reset the warning flag.
                trace!("Activity detected on connection to {}", addr);
                info.last_activity_time = Instant::now();
                info.idle_warning_logged = false;
            } else {
                // No activity, check if the idle threshold has been exceeded.
                let idle_duration = info.last_activity_time.elapsed();
                if idle_duration > idle_threshold && !info.idle_warning_logged {
                    warn!(
                        "Connection to {} has been idle for approximately {:?}.",
                        addr, idle_duration
                    );
                    info.idle_warning_logged = true; // Log only once per idle period.
                }
            }

            // Update the stats for the next comparison.
            info.last_stats = current_stats;
        }
    }
}

/// Handles an incoming TCP connection by proxying it over a QUIC stream with retry logic.
///
/// This function maintains the TCP connection while attempting to establish and
/// re-establish a QUIC stream if it disconnects. It includes limits for both
/// the number of retries and the total session time.
async fn handle_new_tcp_connection(
    tcp_stream: TcpStream,
    remote_addr: SocketAddr,
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
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
        if session_start.elapsed() > retry_config.total_timeout {
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

        let quic_streams = match open_stream_on_best_connection(connections.clone(), strategy).await
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

        let (quic_send, quic_recv) = quic_streams;
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
        let mut buf = [0u8; 4096]; // Use stack-allocated buffer for performance

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
        let mut buf = [0u8; 4096]; // Use stack-allocated buffer for performance

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
    stream_count: Arc<AtomicUsize>,
    tcp_bind_address: String,
) {
    // RAII guard to ensure the stream counter is decremented when the handler finishes.
    struct StreamCounterGuard(Arc<AtomicUsize>);
    impl Drop for StreamCounterGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
            info!("Stream handler finished, decrementing stream count.");
        }
    }
    let _guard = StreamCounterGuard(stream_count);
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

/// Selects the best available QUIC connection based on a given strategy and opens a new stream.
/// This function contains the logic previously in `handle_new_tcp_connection`.
async fn open_stream_on_best_connection(
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
    strategy: ConnectionSelectionStrategy,
) -> Result<(SendStream, RecvStream), Box<dyn Error + Send + Sync>> {
    // Wait for at least one connection to be available, with a timeout.
    const CONNECTION_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    let wait_start = Instant::now();

    loop {
        if !connections.read().await.is_empty() {
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
        let conns_guard = connections.read().await;
        if conns_guard.is_empty() {
            info!("No active QUIC connections available to open a stream.");
            return Err("No active QUIC connections available".into());
        }

        let selected_info = match strategy {
            ConnectionSelectionStrategy::Oldest => {
                conns_guard.values().min_by_key(|info| info.start_time)
            }
            ConnectionSelectionStrategy::Newest => {
                conns_guard.values().max_by_key(|info| info.start_time)
            }
            ConnectionSelectionStrategy::Random => {
                let values: Vec<_> = conns_guard.values().collect();
                values.choose(&mut rand::thread_rng()).copied()
            }
            ConnectionSelectionStrategy::LeastStreams => conns_guard
                .values()
                .min_by_key(|info| info.stream_count.load(Ordering::SeqCst)),
            ConnectionSelectionStrategy::LowestLatency => conns_guard
                .values()
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
            Some(info.connection.clone())
        } else {
            None
        }
    };

    if let Some(connection) = selected_connection {
        info!("Attempting to open a bidirectional stream on the selected connection.");
        match connection.open_bi().await {
            Ok((send, recv)) => {
                info!("Successfully opened a bidirectional stream.");
                Ok((send, recv))
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

/// The central orchestrator for ensuring QUIC connections match DNS records.
///
/// This function acts as a "reconciler". Its primary goal is to ensure that the
/// application's actual state (the set of active `manage_single_quic_connection` tasks)
/// matches the desired state (the set of IP addresses from the latest DNS query).
///
/// It is safe to run repeatedly. If interrupted, the next execution will simply
/// re-evaluate the state and take necessary actions to converge.
///
/// ### Key Steps
/// 1.  **Get Desired State (from DNS)**: Resolves the server's DNS name to get the
///     set of IP addresses we *should* be connected to.
/// 2.  **Reconcile Tasks**: Compares currently running connection tasks with DNS results.
///     - It **stops** tasks for IPs that are no longer in DNS or have already finished.
///     - It **starts** new `manage_single_quic_connection` tasks for IPs that have appeared
///       in DNS but don't have a running task.
///
/// Note: Unlike the previous design, this function does **not** reconcile the shared
/// `connections` dictionary. That responsibility is now fully delegated to the
/// `manage_single_quic_connection` tasks themselves, simplifying the logic here.
async fn reconcile_quic_connections_to_dns(
    server_name: &str,
    server_port: u16,
    endpoint: &quinn::Endpoint,
    stream_tx: &mpsc::Sender<(quinn::SendStream, quinn::RecvStream, Arc<AtomicUsize>)>,
    maintenance_task_handles: &mut HashMap<SocketAddr, tokio::task::JoinHandle<()>>,
    connections: &Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
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

    // Step 2: Reconcile the "Actual State" (running tasks) to match the "Desired State".
    // First, remove tasks for addresses that are no longer in DNS or have finished.
    maintenance_task_handles.retain(|addr, handle| {
        if !latest_addrs.contains(addr) {
            info!(
                "Address {} is no longer in DNS records, stopping its connection task.",
                addr
            );
            handle.abort();
            false // Remove from HashMap
        } else if handle.is_finished() {
            info!(
                "Connection task for {} has finished. It will be removed.",
                addr
            );
            // The task is already finished, so no need to abort.
            // We can optionally await the handle here to log any panics, but for simplicity, we just remove it.
            false // Remove from HashMap
        } else {
            true // Keep in HashMap
        }
    });

    // Then, start new tasks for addresses that have appeared in DNS and are not already running.
    let current_task_addrs: HashSet<_> = maintenance_task_handles.keys().cloned().collect();
    for addr_to_add in latest_addrs.difference(&current_task_addrs) {
        info!(
            "New address {} found in DNS records, starting a new connection manager task.",
            addr_to_add
        );
        let endpoint_clone = endpoint.clone();
        let server_name_clone = server_name.to_string();
        let stream_tx_clone = stream_tx.clone();
        let connections_clone = connections.clone();
        let handle = tokio::spawn(manage_quic_connection(
            endpoint_clone,
            *addr_to_add,
            server_name_clone,
            stream_tx_clone,
            connections_clone,
            endpoint_type,
        ));
        maintenance_task_handles.insert(*addr_to_add, handle);
    }

    info!(
        "Reconciliation complete. {} active QUIC connection tasks.",
        maintenance_task_handles.len(),
    );
}

/// Manages the entire lifecycle of a single QUIC connection in an autonomous task.
///
/// This function is the "worker" spawned by the `reconcile_quic_connections_to_dns` "manager".
/// It embodies a "self-registration and self-cleanup" pattern, making it highly autonomous.
///
/// ### Lifecycle & Responsibilities:
/// 1.  **Connect**: Attempts to establish a QUIC connection to the given `addr`. If it fails,
///     the task simply terminates.
/// 2.  **Register**: Upon successful connection, it creates a `ConnectionInfo` struct and
///     **registers itself** in the shared `connections` map.
/// 3.  **Work & Monitor**: It enters a `tokio::select!` loop to concurrently:
///     -   Accept incoming bidirectional streams from the server and forward them to the
///         central `stream_tx` channel.
///     -   Watch for the connection to be closed for any reason (`connection.closed()`).
/// 4.  **Cleanup (RAII-like)**: Once the connection is closed (either gracefully or due to
///     an error), the `select!` loop terminates. The function then proceeds to its final
///     step: it **removes its own entry** from the shared `connections` map.
/// 5.  **Terminate**: After cleanup, the task finishes its execution.
///
/// This design eliminates the need for a separate `conn_tx` channel and external logic
/// to manage the `connections` map, significantly simplifying the overall architecture.
async fn manage_quic_connection(
    endpoint: quinn::Endpoint,
    addr: SocketAddr,
    server_name: String,
    stream_tx: mpsc::Sender<(quinn::SendStream, quinn::RecvStream, Arc<AtomicUsize>)>,
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionInfo>>>,
    endpoint_type: &'static str,
) {
    let span = info_span!("manage_quic_connection", remote_addr = %addr);
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

        // --- 2. Register ---
        // This task is now responsible for this connection, so add it to the shared map.
        let stream_count = Arc::new(AtomicUsize::new(0));
        let info = ConnectionInfo {
            connection: connection.clone(),
            dest_addr: addr,
            start_time: Instant::now(),
            stream_count: stream_count.clone(),
            last_stats: connection.stats(),
            last_activity_time: Instant::now(),
            idle_warning_logged: false,
            endpoint_type,
        };

        connections.write().await.insert(addr, info);
        info!(
            message = "QUIC connection started",
            startAt = %start_time_utc.to_rfc3339(),
            quic_connection_id = %connection.stable_id(),
            endpoint_type = endpoint_type,
            server_ip = %addr,
        );

        // --- 3. Work (Accept Streams) & Monitor (Watch for Close) ---
        let reason = tokio::select! {
            // This branch waits for the connection to be closed for any reason.
            reason = connection.closed() => {
                reason
            },
            // This branch continuously accepts incoming streams.
            _ = async {
                loop {
                    match connection.accept_bi().await {
                        Ok(streams) => {
                            stream_count.fetch_add(1, Ordering::Relaxed);
                            trace!("Accepted a new bidirectional stream. Active streams: {}", stream_count.load(Ordering::Relaxed));
                            if stream_tx.send((streams.0, streams.1, stream_count.clone())).await.is_err() {
                                stream_count.fetch_sub(1, Ordering::Relaxed);
                                error!("Failed to send new stream to main loop; receiver dropped. Ending stream acceptance.");
                                break; // Main loop is gone, no point in continuing.
                            }
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
        if let Some(removed_info) = connections.write().await.remove(&addr) {
            let terminate_reason = match &reason {
                quinn::ConnectionError::LocallyClosed => "shutdown",
                quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::Reset => "terminatedByPeer",
                quinn::ConnectionError::VersionMismatch
               // | quinn::ConnectionError::FormatError(_) 要確認！！！
                | quinn::ConnectionError::TransportError(_)
                | quinn::ConnectionError::TimedOut
                | quinn::ConnectionError::CidsExhausted => "error",
            };

            info!(
                message = "QUIC connection ended",
                startAt = %start_time_utc.to_rfc3339(),
                quic_connection_id = %removed_info.connection.stable_id(),
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

/// Holds information about an active connection.
#[derive(Debug)]
struct ConnectionInfo {
    /// The QUIC connection handle.
    pub connection: quinn::Connection,
    /// The destination address of the connection.
    pub dest_addr: SocketAddr,
    /// The time the connection was established.
    pub start_time: Instant,
    /// The number of active streams on this connection.
    pub stream_count: Arc<AtomicUsize>,
    /// The last known statistics for this connection, used for idle detection.
    pub last_stats: quinn::ConnectionStats,
    /// The approximate time of the last detected data transfer on this connection.
    pub last_activity_time: Instant,
    /// A flag to prevent spamming idle warnings. True if a warning has already been logged.
    pub idle_warning_logged: bool,
    /// The type of endpoint this connection belongs to (e.g., "provider", "consumer").
    pub endpoint_type: &'static str,
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
