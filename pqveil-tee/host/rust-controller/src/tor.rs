// SPDX-License-Identifier: BSD-2-Clause
//! Tor Control Port & Service Monitor
//!
//! Queries Tor ControlPort (127.0.0.1:9051) for bootstrap phase
//! and circuit status without relying on external websites.

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use std::fs;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct TorStatus {
    pub bootstrapped: bool,
    pub bootstrap_percentage: u8,
    pub circuit_established: bool,
}

pub struct TorMonitor {
    control_addr: String,
    cookie_path: String,
}

impl TorMonitor {
    pub fn new() -> Self {
        Self {
            control_addr: "127.0.0.1:9051".to_string(),
            cookie_path: "/var/run/tor/control.authcookie".to_string(),
        }
    }

    pub async fn check_status(&self) -> Result<TorStatus> {
        let stream = match TcpStream::connect(&self.control_addr).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Cannot connect to Tor ControlPort: {}", e);
                return Ok(TorStatus {
                    bootstrapped: false,
                    bootstrap_percentage: 0,
                    circuit_established: false,
                });
            }
        };

        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // 1. Authenticate
        let auth_cmd = if Path::new(&self.cookie_path).exists() {
            let cookie = fs::read(&self.cookie_path)
                .context("Failed reading Tor control cookie")?;
            format!("AUTHENTICATE {}\r\n", hex::encode(cookie))
        } else {
            "AUTHENTICATE \"\"\r\n".to_string()
        };

        writer.write_all(auth_cmd.as_bytes()).await?;
        if let Some(resp) = lines.next_line().await? {
            if !resp.starts_with("250") {
                bail!("Tor authentication failed: {}", resp);
            }
        }

        // 2. Query bootstrap-phase
        writer.write_all(b"GETINFO status/bootstrap-phase\r\n").await?;
        let mut percentage = 0;
        let mut bootstrapped = false;
        while let Some(line) = lines.next_line().await? {
            if line.contains("PROGRESS=") {
                if let Some(idx) = line.find("PROGRESS=") {
                    let sub = &line[idx + 9..];
                    let end = sub.find(' ').unwrap_or(sub.len());
                    percentage = sub[..end].parse::<u8>().unwrap_or(0);
                    if percentage == 100 {
                        bootstrapped = true;
                    }
                }
            }
            if line.starts_with("250 OK") {
                break;
            }
        }

        // 3. Query circuit-established
        writer.write_all(b"GETINFO status/circuit-established\r\n").await?;
        let mut circuit_established = false;
        while let Some(line) = lines.next_line().await? {
            if line.contains("status/circuit-established=1") {
                circuit_established = true;
            }
            if line.starts_with("250 OK") {
                break;
            }
        }

        // 4. Quit session
        let _ = writer.write_all(b"QUIT\r\n").await;

        Ok(TorStatus {
            bootstrapped,
            bootstrap_percentage: percentage,
            circuit_established,
        })
    }
}

