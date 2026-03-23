//! # SPN Consumer Agent
//!
//! `spn` is an infrastructure system for building and managing distributed component applications,
//! particularly those that are containerized. The `spn` system consists of two main parts that
//! work in tandem: `spn_hub` and `spn_agent`.
//!
//! This binary implements the **Consumer** agent. It connects to the SPN Hub and exposes a local
//! TCP listener. Traffic received on this local listener is forwarded via QUIC streams through
//! the Hub to a target Provider.
//!
//! ## Usage
//! To run the consumer with info-level logging:
//! ```sh
//! RUST_LOG=info cargo run --bin consumer
//! ```

use clap::Parser;

use ep_lib::core;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SPN_HUB_HOSTNAME")]
    spn_hub_hostname: String,
    #[arg(long, env = "SPN_HUB_PORT", default_value = "4433")]
    spn_hub_port: u16,
    #[arg(long, env = "SPN_AGENT_TRUST_CERTIFICATE_ROOT")]
    spn_agent_trust_cert_ca: String,
    #[arg(long, env = "SPN_AGENT_CLIENT_CERTIFICATE")]
    spn_agent_client_cert: String,
    #[arg(long, env = "SPN_AGENT_CLIENT_CERTIFICATE_KEY")]
    spn_agent_client_cert_key: String,
    #[arg(long, env = "BIND_ADDRESS")]
    bind_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    core::run_client_consumer(
        &args.spn_hub_hostname,
        args.spn_hub_port,
        args.spn_agent_trust_cert_ca.as_ref(),
        args.spn_agent_client_cert.as_ref(),
        args.spn_agent_client_cert_key.as_ref(),
        args.bind_address.as_ref(),
    )
    .await
}
