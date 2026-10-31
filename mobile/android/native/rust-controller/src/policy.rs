// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Network Policy Engine (Fail-Closed Enforcement)

use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    monotonic_version: u64,
    fail_closed_active: bool,
    block_raw_udp: bool,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            monotonic_version: 1,
            fail_closed_active: true,
            block_raw_udp: true,
        }
    }

    pub fn version(&self) -> u64 {
        self.monotonic_version
    }

    /// Update policy version with strictly monotonic check
    pub fn update_policy(&mut self, new_version: u64) -> Result<()> {
        if new_version <= self.monotonic_version {
            bail!(
                "Policy rollback rejected: new version {} <= current {}",
                new_version,
                self.monotonic_version
            );
        }
        self.monotonic_version = new_version;
        log::info!("Policy updated to version {}", self.monotonic_version);
        Ok(())
    }

    /// Validates if an outbound packet is permitted
    pub fn is_packet_allowed(&self, is_tcp: bool, is_dns: bool, is_udp: bool) -> bool {
        if !self.fail_closed_active {
            return false;
        }
        if is_tcp || is_dns {
            return true;
        }
        if is_udp && self.block_raw_udp {
            // Block non-DNS UDP in v1 as per architecture rules
            return false;
        }
        false
    }
}

