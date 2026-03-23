//! # SPN Provider Agent
//!
//! `spn` is an infrastructure system for building and managing distributed component applications,
//! particularly those that are containerized. The `spn` system consists of two main parts that
//! work in tandem: `spn_hub` and `spn_agent`.
//!
//! This binary implements the **Provider** agent. It connects to the SPN Hub and waits for
//! incoming streams. When a stream is accepted, it connects to a local service (the "Forward Address")
//! and proxies traffic between the Hub and the local service.
//!
//! ## Usage
//! To run the provider with info-level logging:
//! ```sh
//! RUST_LOG=info cargo run --bin provider
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
    #[arg(long, env = "FORWARD_ADDRESS")]
    forward_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    core::run_client_provider(
        &args.spn_hub_hostname,
        args.spn_hub_port,
        args.spn_agent_trust_cert_ca.as_ref(),
        args.spn_agent_client_cert.as_ref(),
        args.spn_agent_client_cert_key.as_ref(),
        args.forward_address.as_ref(),
    )
    .await
}
