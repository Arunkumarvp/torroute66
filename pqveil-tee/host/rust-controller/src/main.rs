// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil-TEE Host Controller
//!
//! Orchestrates the normal-world services:
//! - Interacts with OP-TEE Trusted Application via `TeeClient`
//! - Monitors Tor daemon bootstrapping and status
//! - Drives post-quantum hybrid VPN handshake
//! - Generates signed health reports
//! - Supervises fail-closed network policies

use anyhow::Result;
use log::{error, info, warn};
use std::time::Duration;
use tokio::signal;
use tokio::time::sleep;

mod health;
mod tee_client;
mod tor;
mod vpn;

use health::HealthService;
use tee_client::TeeClient;
use tor::TorMonitor;
use vpn::VpnClient;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("============================================================");
    info!(" Starting PQVeil-TEE Host Controller (2026)");
    info!("============================================================");

    // 1. Connect to OP-TEE
    info!("[1/5] Initializing connection to Secure World (OP-TEE)...");
    let mut tee = match TeeClient::new() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to initialize TEE client: {}", e);
            return Err(e);
        }
    };

    // 2. Query TA Status and Provision if needed
    let status = tee.get_status()?;
    info!(
        "TA Status: v{}.{} | Monotonic Counter: {} | Provisioned: {}",
        status.version_major, status.version_minor, status.monotonic_counter, status.provisioned
    );

    if !status.provisioned {
        info!("TA not yet provisioned. Performing one-time provisioning...");
        let pk = tee.provision()?;
        info!(
            "Provisioning complete. Long-term ML-DSA-65 public key size: {} bytes",
            pk.len()
        );
    }

    // 3. Monitor Tor Daemon
    info!("[2/5] Checking Tor connectivity...");
    let tor_monitor = TorMonitor::new();
    match tor_monitor.check_status().await {
        Ok(tor_st) => {
            info!(
                "Tor daemon: bootstrapped={}% circuit_established={}",
                tor_st.bootstrap_percentage, tor_st.circuit_established
            );
        }
        Err(e) => {
            warn!("Tor daemon status query warning: {}", e);
        }
    }

    // 4. Initialize VPN Client
    let target_onion = "pqveilv3hiddenendpointexample.onion";
    let target_port = 8443;
    let vpn_client = VpnClient::new(target_onion, target_port);

    // 5. Initialize Health Service
    let health_svc = HealthService::new();

    info!("[3/5] Starting periodic Health & Attestation task...");
    let health_report = health_svc
        .generate_signed_health_report(&mut tee, vpn_client.is_active())
        .await?;
    info!(
        "Initial Health Statement signed by TA. Length: {} bytes",
        health_report.len()
    );

    info!("[4/5] Controller initialization complete.");
    info!("Press Ctrl+C to terminate controller.");

    // Supervision loop
    loop {
        tokio::select! {
            _ = sleep(Duration::from_secs(30)) => {
                let _ = health_svc.generate_signed_health_report(&mut tee, vpn_client.is_active()).await;
            }
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received. Cleaning up...");
                break;
            }
        }
    }

    info!("PQVeil Controller exited cleanly.");
    Ok(())
}

