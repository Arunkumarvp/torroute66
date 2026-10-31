// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Health & Attestation Service
//!
//! Gathers local Tor and VPN tunnel status, binds with a fresh nonce,
//! and requests the TA to cryptographically sign the health statement
//! with the sealed ML-DSA-65 identity key.

use anyhow::Result;
use log::info;
use rand::RngCore;

use crate::tee_client::TeeClient;
use crate::tor::TorMonitor;

pub struct HealthService {
    tor_monitor: TorMonitor,
}

impl HealthService {
    pub fn new() -> Self {
        Self {
            tor_monitor: TorMonitor::new(),
        }
    }

    pub async fn generate_signed_health_report(
        &self,
        tee: &mut TeeClient,
        vpn_tunnel_active: bool,
    ) -> Result<Vec<u8>> {
        // 1. Check Tor Status
        let tor_status = self.tor_monitor.check_status().await?;

        // 2. Compute flags:
        //    Bit 0: Tor Bootstrapped & Circuit established
        //    Bit 1: VPN Tunnel Active
        let mut flags: u32 = 0;
        if tor_status.bootstrapped && tor_status.circuit_established {
            flags |= 1 << 0;
        }
        if vpn_tunnel_active {
            flags |= 1 << 1;
        }

        // 3. Generate 16-byte fresh challenge nonce
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        // 4. Request signature from the TA
        let signed_report = tee.sign_health(&nonce, flags)?;

        info!(
            "Health report signed by TA: tor_ok={} vpn_ok={} report_len={}",
            (flags & 1) != 0,
            (flags & 2) != 0,
            signed_report.len()
        );

        Ok(signed_report)
    }
}

