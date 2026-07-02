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
use crate::commands::auth::{
    clear_lockdown_with_recovery_key, initialize_vault, login, logout,
    reset_admin_password_with_recovery_key, session_check,
};
use crate::commands::user::{delete_request, download_file, list_files, upload_file};
use crate::manifest::verify_or_create_manifest;
use crate::models::ManifestRuntimeStatus;
use crate::state::AppState;
use crate::vault::VaultStore;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use tauri::Manager;

fn main() {
    configure_portable_webview2_runtime();

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
            reset_admin_password_with_recovery_key,
            clear_lockdown_with_recovery_key,
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

#[cfg(windows)]
fn configure_portable_webview2_runtime() {
    if std::env::var_os("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER").is_some() {
        return;
    }

    let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return;
    };

    let fixed_runtime_root = exe_dir.join("WebView2FixedRuntime");
    if let Some(browser_folder) = fixed_runtime_browser_folder(&fixed_runtime_root) {
        std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", browser_folder);
    }
}

#[cfg(not(windows))]
fn configure_portable_webview2_runtime() {}

#[cfg(windows)]
fn fixed_runtime_browser_folder(root: &Path) -> Option<PathBuf> {
    if root.join("msedgewebview2.exe").is_file() {
        return Some(root.to_path_buf());
    }

    let mut child_dirs = std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            path.is_dir().then_some(path)
        })
        .collect::<Vec<_>>();

    child_dirs.sort();
    child_dirs
        .into_iter()
        .find(|path| path.join("msedgewebview2.exe").is_file())
}

#[cfg(all(test, windows))]
mod windows_webview2_tests {
    use super::fixed_runtime_browser_folder;

    #[test]
    fn fixed_runtime_browser_folder_accepts_nested_runtime() {
        let root =
            std::env::temp_dir().join(format!("shield-webview2-test-{}", std::process::id()));
        let nested = root.join("Microsoft.WebView2.FixedVersionRuntime.test.x64");
        std::fs::create_dir_all(&nested).expect("create nested runtime dir");
        std::fs::write(nested.join("msedgewebview2.exe"), b"test").expect("write marker exe");

        let resolved = fixed_runtime_browser_folder(&root).expect("detect nested runtime");
        assert_eq!(resolved, nested);

        let _ = std::fs::remove_dir_all(root);
    }
}
