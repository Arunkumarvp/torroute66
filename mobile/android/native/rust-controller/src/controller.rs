// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Core Security Controller

use anyhow::Result;
use std::sync::{Arc, Mutex};

use crate::health::HealthMonitor;
use crate::key_backend::{AndroidKeystoreBackend, BackendInfo, KeyBackendType, OpteeBackend, SecureKeyBackend};
use crate::policy::PolicyEngine;
use crate::session::{SessionManager, SessionState};

pub struct PqveilController {
    backend: Box<dyn SecureKeyBackend>,
    session: SessionManager,
    policy: PolicyEngine,
}

impl PqveilController {
    pub fn new(backend_type: KeyBackendType) -> Self {
        let backend: Box<dyn SecureKeyBackend> = match backend_type {
            KeyBackendType::AndroidKeystore => Box::new(AndroidKeystoreBackend::new(true)),
            KeyBackendType::OpteeTrustZone => Box::new(OpteeBackend::new()),
            KeyBackendType::MockTest => Box::new(AndroidKeystoreBackend::new(false)),
        };

        Self {
            backend,
            session: SessionManager::new(),
            policy: PolicyEngine::new(),
        }
    }

    pub fn get_backend_info(&self) -> Result<BackendInfo> {
        self.backend.get_info()
    }

    pub fn session_state(&self) -> &SessionState {
        self.session.state()
    }

    pub fn start_connection(&mut self, onion_target: &str) -> Result<()> {
        self.session.transition(SessionState::BootstrappingTor { percentage: 25 });
        // Transition sequence simulated for Phase 1
        self.session.transition(SessionState::ConnectingOnion { target: onion_target.to_string() });
        self.session.transition(SessionState::HandshakePQ);

        let transcript_hash = [0x5Au8; 32];
        let sig = self.backend.sign_transcript(&transcript_hash)?;
        log::info!("Handshake authenticated with signature length: {} B", sig.len());

        self.session.transition(SessionState::Connected {
            session_id: "session-pqc-001".to_string(),
        });
        Ok(())
    }

    pub fn stop_connection(&mut self) {
        self.session.transition(SessionState::Disconnected);
    }

    pub fn generate_health_report(&mut self) -> Result<Vec<u8>> {
        let tor_ok = true;
        let vpn_ok = matches!(self.session.state(), SessionState::Connected { .. });
        HealthMonitor::generate_attested_health_statement(self.backend.as_mut(), tor_ok, vpn_ok)
    }
}

