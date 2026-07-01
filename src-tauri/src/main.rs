#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod archive;
mod audit;
mod commands;
mod crypto;
mod error;
mod manifest;
mod models;
mod state;
mod vault;

use crate::commands::admin::{
    admin_audit_logs, admin_audit_tables, admin_clear_lockdown, admin_crypto_erase_vault,
    admin_destroy_file, admin_export_audit_logs, admin_export_custody_report, admin_recover_file,
    admin_recovery_queue, admin_reset_user_password, admin_security_summary, admin_tamper_alerts,
};
use crate::commands::auth::{initialize_vault, login, logout, session_check};
use crate::commands::user::{delete_request, download_file, list_files, upload_file};
use crate::manifest::verify_or_create_manifest;
use crate::models::ManifestRuntimeStatus;
use crate::state::AppState;
use crate::vault::VaultStore;
use tauri::Manager;

fn main() {
    let store = VaultStore::portable().expect("failed to resolve portable vault root");
    let (manifest_status, startup_lockdown_reason) =
        match verify_or_create_manifest(&store.paths().root) {
            Ok(status) => (status, None),
            Err(error) => (
                ManifestRuntimeStatus {
                    status: "INVALID".to_string(),
                    drive_id: None,
                    message: error.to_string(),
                },
                Some(error.to_string()),
            ),
        };

    let initialized = tauri::async_runtime::block_on(store.is_initialized()).unwrap_or(false);
    let app_state = AppState::new(store, initialized, manifest_status);

    tauri::Builder::default()
        .manage(app_state)
        .setup(move |app| {
            let state = app.state::<AppState>();
            let startup_lockdown_reason = startup_lockdown_reason.clone();
            tauri::async_runtime::block_on(async {
                if let Some(reason) = startup_lockdown_reason {
                    state.enter_lockdown(reason).await;
                    return;
                }

                if let Ok(Some(reason)) = state.store.persistent_lockdown_reason().await {
                    state.enter_lockdown(reason).await;
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            initialize_vault,
            login,
            logout,
            session_check,
            list_files,
            upload_file,
            download_file,
            delete_request,
            admin_audit_logs,
            admin_audit_tables,
            admin_export_audit_logs,
            admin_recovery_queue,
            admin_recover_file,
            admin_destroy_file,
            admin_reset_user_password,
            admin_security_summary,
            admin_tamper_alerts,
            admin_clear_lockdown,
            admin_export_custody_report,
            admin_crypto_erase_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running Secure Portable Vault backend");
}
