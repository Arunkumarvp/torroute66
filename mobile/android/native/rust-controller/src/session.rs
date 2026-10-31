// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Session State Machine

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Disconnected,
    BootstrappingTor { percentage: u8 },
    ConnectingOnion { target: String },
    HandshakePQ,
    Connected { session_id: String },
    Reconnecting { attempt: u32 },
    Failed { reason: String },
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::Disconnected
    }
}

pub struct SessionManager {
    current_state: SessionState,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            current_state: SessionState::Disconnected,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.current_state
    }

    pub fn transition(&mut self, new_state: SessionState) {
        log::info!("Session state transition: {:?} -> {:?}", self.current_state, new_state);
        self.current_state = new_state;
    }
}

