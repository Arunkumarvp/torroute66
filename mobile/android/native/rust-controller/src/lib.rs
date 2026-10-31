// SPDX-License-Identifier: BSD-2-Clause
//! PQVeil Mobile JNI Bridge & Native Security Controller Entry Point

pub mod controller;
pub mod health;
pub mod key_backend;
pub mod policy;
pub mod session;

use controller::PqveilController;
use key_backend::KeyBackendType;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use std::sync::Mutex;

static CONTROLLER: Mutex<Option<PqveilController>> = Mutex::new(None);

#[no_mangle]
pub extern "system" fn Java_org_pqveil_app_service_NativeBridge_initController(
    mut env: JNIEnv,
    _class: JClass,
    backend_code: jint,
) -> jboolean {
    let backend_type = match backend_code {
        0 => KeyBackendType::AndroidKeystore,
        1 => KeyBackendType::OpteeTrustZone,
        _ => KeyBackendType::MockTest,
    };

    let controller = PqveilController::new(backend_type);
    let mut guard = match CONTROLLER.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    *guard = Some(controller);
    log::info!("PQVeil native controller initialized successfully");
    1
}

#[no_mangle]
pub extern "system" fn Java_org_pqveil_app_service_NativeBridge_getBackendInfo(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let guard = match CONTROLLER.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("Error: Controller Lock Failed").unwrap().into_raw(),
    };

    if let Some(ref c) = *guard {
        if let Ok(info) = c.get_backend_info() {
            let desc = format!(
                "Backend: {} | Hardware-Isolated: {} | Status: {}",
                info.security_level_desc, info.is_hardware_backed, if info.provisioned { "Provisioned" } else { "Unprovisioned" }
            );
            return env.new_string(desc).unwrap().into_raw();
        }
    }

    env.new_string("Uninitialized").unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_org_pqveil_app_service_NativeBridge_startTunnel(
    mut env: JNIEnv,
    _class: JClass,
    onion_target: JString,
) -> jboolean {
    let target_str: String = match env.get_string(&onion_target) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let mut guard = match CONTROLLER.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    if let Some(ref mut c) = *guard {
        if c.start_connection(&target_str).is_ok() {
            return 1;
        }
    }
    0
}

#[no_mangle]
pub extern "system" fn Java_org_pqveil_app_service_NativeBridge_stopTunnel(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut guard = match CONTROLLER.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    if let Some(ref mut c) = *guard {
        c.stop_connection();
        return 1;
    }
    0
}

#[no_mangle]
pub extern "system" fn Java_org_pqveil_app_service_NativeBridge_getHealthReport(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let mut guard = match CONTROLLER.lock() {
        Ok(g) => g,
        Err(_) => return env.new_string("Error: Controller Lock Failed").unwrap().into_raw(),
    };

    if let Some(ref mut c) = *guard {
        if let Ok(report) = c.generate_health_report() {
            let res = format!("Attested Health Report: {} bytes (ML-DSA-65 signed)", report.len());
            return env.new_string(res).unwrap().into_raw();
        }
    }
    env.new_string("Error generating health report").unwrap().into_raw()
}

