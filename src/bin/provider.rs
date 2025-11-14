// spn is an infrastructure system for building and managing distributed component applications,
// particularly those that are containerized. The spn system consists of two main parts that
// work in tandem: spn_hub and spn_agent. This is the source code for spnagent/provider.
//
// USAGE:
//   To run the consumer with info-level logging:
//   RUST_LOG=info cargo run --bin provider
//
// TODO:
//   - Refactor the names of the environment variables used for startup configuration.
use clap::Parser;

use ep_lib::client_core;

#[derive(Parser)]
struct Args {
    #[arg(
        long,
        env = "FC_SERVER_HOSTNAME",
        default_value = "spnhub.wgd.example.com"
    )]
    fc_server_hostname: String,
    #[arg(long, env = "FC_SERVER_PORT", default_value = "4433")]
    fc_server_port: u16,
    #[arg(
        long,
        env = "FC_AGENT_TRUST_CERTIFICATE_ROOT",
        default_value = "../cert_server/ca.pem"
    )]
    fc_agent_turst_cert_ca: String,
    #[arg(
        long,
        env = "FC_AGENT_CLIENT_CERTIFICATE",
        default_value = "../cert_client/provider.pem"
    )]
    fc_agent_client_cert: String,
    #[arg(
        long,
        env = "FC_AGENT_CLIENT_CERTIFICATE_KEY",
        default_value = "../cert_client/provider-key.pem"
    )]
    fc_agent_client_cert_key: String,
    #[arg(long, env = "FC_BIND_ADDRESS", default_value = "127.0.0.11:9001")]
    fc_bind_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    client_core::run_client_provider(
        &args.fc_server_hostname,
        args.fc_server_port,
        args.fc_agent_turst_cert_ca.as_ref(),
        args.fc_agent_client_cert.as_ref(),
        args.fc_agent_client_cert_key.as_ref(),
        args.fc_bind_address.as_ref(),
    )
    .await
}
