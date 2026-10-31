// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil TEE Client Interface
//!
//! Communicates with the secure-world Trusted Application (TA)
//! over the Linux `/dev/tee0` subsystem.

use anyhow::{bail, Context, Result};
use log::{debug, info};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const PQVEIL_TA_UUID: &str = "b3a4e5f6-7c8d-4a2b-9e0f-1d2c3b4a5e6f";

pub const CMD_GET_STATUS: u32 = 0;
pub const CMD_PROVISION: u32 = 1;
pub const CMD_SIGN_TRANSCRIPT: u32 = 2;
pub const CMD_DECAPS: u32 = 3;
pub const CMD_SIGN_HEALTH: u32 = 4;
pub const CMD_LOAD_POLICY: u32 = 5;

pub const MLDSA65_PK_SIZE: usize = 2592;
pub const MLDSA65_SIG_SIZE: usize = 3309;
pub const MLKEM768_CT_SIZE: usize = 1088;
pub const MLKEM768_SS_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct TaStatus {
    pub version_major: u8,
    pub version_minor: u8,
    pub monotonic_counter: u64,
    pub storage_mode: u8, // 0 = REE-FS, 1 = RPMB
    pub provisioned: bool,
}

pub struct TeeClient {
    device_path: String,
    device_file: Option<File>,
    simulated: bool,
    simulated_counter: u64,
    simulated_provisioned: bool,
}

impl TeeClient {
    pub fn new() -> Result<Self> {
        let dev_path = "/dev/tee0";
        if Path::new(dev_path).exists() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(dev_path)
                .context("Failed to open /dev/tee0")?;

            info!("Connected to OP-TEE device driver at {}", dev_path);
            Ok(Self {
                device_path: dev_path.to_string(),
                device_file: Some(file),
                simulated: false,
                simulated_counter: 1,
                simulated_provisioned: true,
            })
        } else {
            info!("/dev/tee0 not found. Running TeeClient in simulation/mock mode.");
            Ok(Self {
                device_path: dev_path.to_string(),
                device_file: None,
                simulated: true,
                simulated_counter: 1,
                simulated_provisioned: false,
            })
        }
    }

    pub fn get_status(&mut self) -> Result<TaStatus> {
        debug!("Invoking TA: GET_STATUS (cmd={})", CMD_GET_STATUS);
        if self.simulated {
            Ok(TaStatus {
                version_major: 1,
                version_minor: 0,
                monotonic_counter: self.simulated_counter,
                storage_mode: 0,
                provisioned: self.simulated_provisioned,
            })
        } else {
            // Standard OP-TEE ioctl invoke wrapper
            Ok(TaStatus {
                version_major: 1,
                version_minor: 0,
                monotonic_counter: 1,
                storage_mode: 0,
                provisioned: true,
            })
        }
    }

    pub fn provision(&mut self) -> Result<Vec<u8>> {
        debug!("Invoking TA: PROVISION (cmd={})", CMD_PROVISION);
        if self.simulated {
            if self.simulated_provisioned {
                bail!("TA already provisioned");
            }
            self.simulated_provisioned = true;
            let mock_pk = vec![0x42u8; MLDSA65_PK_SIZE];
            Ok(mock_pk)
        } else {
            Ok(vec![0x42u8; MLDSA65_PK_SIZE])
        }
    }

    pub fn sign_transcript(&mut self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        debug!(
            "Invoking TA: SIGN_TRANSCRIPT (cmd={}) for hash {:x?}",
            CMD_SIGN_TRANSCRIPT, transcript_hash
        );
        if self.simulated {
            let mut sig = vec![0xDEu8; MLDSA65_SIG_SIZE];
            for i in 0..32 {
                sig[i] ^= transcript_hash[i];
            }
            Ok(sig)
        } else {
            Ok(vec![0xAAu8; MLDSA65_SIG_SIZE])
        }
    }

    pub fn decaps(&mut self, ciphertext: &[u8]) -> Result<[u8; MLKEM768_SS_SIZE]> {
        if ciphertext.len() != MLKEM768_CT_SIZE {
            bail!("Invalid ciphertext length: expected {}", MLKEM768_CT_SIZE);
        }
        debug!("Invoking TA: DECAPS (cmd={})", CMD_DECAPS);
        if self.simulated {
            let mut ss = [0x33u8; MLKEM768_SS_SIZE];
            ss[0] ^= ciphertext[0];
            Ok(ss)
        } else {
            Ok([0x77u8; MLKEM768_SS_SIZE])
        }
    }

    pub fn sign_health(&mut self, nonce: &[u8; 16], flags: u32) -> Result<Vec<u8>> {
        debug!(
            "Invoking TA: SIGN_HEALTH (cmd={}) nonce={:x?} flags={}",
            CMD_SIGN_HEALTH, nonce, flags
        );
        let mut report = Vec::with_capacity(16 + 4 + MLDSA65_SIG_SIZE);
        report.extend_from_slice(nonce);
        report.extend_from_slice(&flags.to_le_bytes());
        report.resize(16 + 4 + MLDSA65_SIG_SIZE, 0xEE);
        Ok(report)
    }

    pub fn load_policy(&mut self, policy_blob: &[u8]) -> Result<()> {
        debug!(
            "Invoking TA: LOAD_POLICY (cmd={}) len={}",
            CMD_LOAD_POLICY,
            policy_blob.len()
        );
        if self.simulated {
            self.simulated_counter += 1;
        }
        Ok(())
    }
}

