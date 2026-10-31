// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Health & Attestation Module

use crate::key_backend::SecureKeyBackend;
use anyhow::Result;
use rand::RngCore;

pub struct HealthMonitor;

impl HealthMonitor {
    pub fn generate_attested_health_statement(
        backend: &mut dyn SecureKeyBackend,
        tor_ok: bool,
        vpn_ok: bool,
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut flags: u32 = 0;
        if tor_ok {
            flags |= 1 << 0;
        }
        if vpn_ok {
            flags |= 1 << 1;
        }

        backend.sign_health(&nonce, flags)
    }
}

