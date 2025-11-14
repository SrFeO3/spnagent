use std::error::Error;
use std::sync::Arc;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use tokio::time::Duration;
use std::net::ToSocketAddrs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::parse_x509_certificate;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

// cpnst
const MAX_CONCURRENT_UNI_STREAMS: u8 = 0;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 50;
const MAX_IDLE_TIMEOUT_SECS: u64 = 60;

/// Initializes the tracing subscriber for logging.
pub fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .with_current_span(false)
        .init();
}

/// Installs the default crypto provider.
pub fn initialize_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("could not install default crypto provider");
}

/// Loads client certificates, a private key, and a trust store from PEM files.
///
/// # Arguments
///
/// * `my_cert_path`: Path to the my certificate PEM file.
/// * `my_key_path`: Path to the my private key PEM file.
/// * `trust_ca_cert_path`: Path to the trusted CA certificate(s) PEM file.
pub fn load_certs_and_key(
    my_cert_path: &str,
    my_key_path: &str,
    trust_ca_cert_path: &str,
) -> Result<
    (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        quinn::rustls::RootCertStore,
    ),
    Box<dyn Error>,
> {
    let certs = CertificateDer::pem_file_iter(my_cert_path)?
        .map(|cert_result| cert_result.map_err(|e| e.into()))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let key = PrivateKeyDer::from_pem_file(my_key_path)?;

    let mut truststore = quinn::rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(trust_ca_cert_path)? {
        truststore.add(cert?)?;
    }

    Ok((certs, key, truststore))
}

/// Creates and configures a QUIC client endpoint.
///
/// This function sets up the TLS configuration with client authentication,
/// ALPN protocols, and transport parameters like keep-alive and idle timeout.
///
/// # Arguments
///
/// * `certs`: A vector of `CertificateDer` representing the client's certificate chain.
/// * `key`: The client's private key as a `PrivateKeyDer`.
/// * `truststore`: A `RootCertStore` containing the trusted CA certificates for server verification.
/// * `alpn_protocols`: A slice of byte slices, where each represents a supported ALPN protocol to be advertised to the server.
///
/// # Returns
///
/// A `Result` containing the configured `quinn::Endpoint` on success, or a `Box<dyn Error>` on failure.
pub fn create_quic_client_endpoint(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    truststore: quinn::rustls::RootCertStore,
    alpn_protocols: &[&[u8]],
) -> Result<quinn::Endpoint, Box<dyn Error>> {
    let mut client_config = quinn::rustls::ClientConfig::builder()
        .with_root_certificates(truststore)
        .with_client_auth_cert(certs, key)
        .expect("invalid client certs/key");
    client_config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();

    let mut quic_client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_config)?));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)))
        .max_idle_timeout(Some(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS).try_into()?));
    quic_client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quic_client_config);
    Ok(endpoint)
}

/// Creates and configures a QUIC server endpoint.
///
/// This function sets up the TLS configuration to require client authentication,
/// configures ALPN protocols, and sets transport parameters such as keep-alive and idle timeout.
/// It then binds the endpoint to the specified address and port.
///
/// # Arguments
///
/// * `sc_server_address`: The IP address for the server to listen on.
/// * `sc_server_port`: The port for the server to listen on.
/// * `certs`: A vector of `CertificateDer` representing the server's certificate chain.
/// * `key`: The server's private key as a `PrivateKeyDer`.
/// * `truststore`: A `RootCertStore` containing trusted CA certificates for client verification.
/// * `alpn_protocols`: A slice of byte slices, where each represents a supported ALPN protocol.
///
/// # Returns
///
/// A `Result` containing the configured `quinn::Endpoint` on success, or a `Box<dyn Error>` on failure.
pub fn create_quic_server_endpoint(
    sc_server_address: &String,
    sc_server_port: u16,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    truststore: quinn::rustls::RootCertStore,
    alpn_protocols: &[&[u8]],
) -> Result<quinn::Endpoint, Box<dyn Error>> {
    let cert_verifier = quinn::rustls::server::WebPkiClientVerifier::builder(Arc::new(truststore))
        //.allow_unauthenticated()
        .build()
        .unwrap();

    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(cert_verifier)
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = alpn_protocols.iter().map(|&x| x.into()).collect();

    let server_addrs = (sc_server_address.to_string(), sc_server_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    let mut quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(Arc::new(server_config))?,
    ));
    Arc::get_mut(&mut quinn_server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into())
        .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)))
        .max_idle_timeout(Some(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS).try_into()?));

    let endpoint = quinn::Endpoint::server(quinn_server_config, server_addrs)?;

    Ok(endpoint)
}

pub async fn check_and_get_info_connection(
    connection: quinn::Connection,
) -> (Option<String>, Option<String>) {
    let mut cn = None;

    // certificate
    if let Some(identity) = connection.peer_identity() {
        if let Some(certs) = identity.downcast_ref::<Vec<CertificateDer<'static>>>() {
            if let Some(client_cert) = certs.first() {
                if let Ok((_, parsed_cert)) = parse_x509_certificate(client_cert.as_ref()) {
                    info!("  - Subject: {}", parsed_cert.subject());
                    info!("  - Issuer:  {}", parsed_cert.issuer());
                    info!("  - Serial:  {}", parsed_cert.serial);

                    // CN (Common Name)
                    cn = parsed_cert
                        .subject()
                        .iter()
                        .flat_map(|rdn| rdn.iter())
                        .find(|attr| attr.attr_type() == &OID_X509_COMMON_NAME)
                        .and_then(|attr| attr.attr_value().as_str().ok())
                        .map(String::from);

                    if let Some(cn_val) = &cn {
                        info!("  - CN:      {}", cn_val);
                    } else {
                        info!("  - CN:      Not found");
                    }
                } else {
                    error!("Failed to parse client certificate.");
                }
            }
        }
    } else {
        info!("Client did not present a certificate.");
    }

    // ALPN
    let alpn = connection.handshake_data().and_then(|data| {
        data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            .and_then(|h| h.protocol.as_ref())
            .map(|p| String::from_utf8_lossy(p).into_owned())
    });

    if let Some(alpn_val) = &alpn {
        info!("ALPN is {}", alpn_val);
    } else {
        info!("No ALPN protocol negotiated.");
    }

    (cn, alpn)
}
