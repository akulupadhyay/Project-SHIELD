use crate::error::{CommandError, CommandResult, VaultError};
use crate::models::{
    AuditExportResult, AuditTables, AuditView, CryptoEraseResult, CustodyExportResult,
    RecoveryView, SecuritySummary, SessionStatus, TamperAlert,
};
use crate::state::AppState;
use crate::vault::path_from_external_input;
use secrecy::SecretString;
use tauri::State;

#[tauri::command]
pub async fn admin_audit_logs(state: State<'_, AppState>) -> CommandResult<Vec<AuditView>> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .audit_logs(&keys)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_audit_tables(state: State<'_, AppState>) -> CommandResult<AuditTables> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .audit_tables(&keys)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_export_audit_logs(
    state: State<'_, AppState>,
    category: String,
) -> CommandResult<AuditExportResult> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .export_audit_logs(&keys, category)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_recovery_queue(state: State<'_, AppState>) -> CommandResult<Vec<RecoveryView>> {
    state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .recovery_queue()
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_recover_file(
    state: State<'_, AppState>,
    file_id: String,
) -> CommandResult<RecoveryView> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .recover_file(&keys, file_id)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_destroy_file(
    state: State<'_, AppState>,
    file_id: String,
) -> CommandResult<RecoveryView> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .destroy_file(&keys, file_id)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_reset_user_password(
    state: State<'_, AppState>,
    new_user_passphrase: String,
) -> CommandResult<()> {
    if new_user_passphrase.len() < 12 {
        return Err(CommandError::from(VaultError::InvalidInput(
            "new_user_passphrase must be at least 12 characters".to_string(),
        )));
    }

    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .reset_user_password(&keys, SecretString::new(new_user_passphrase))
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_tamper_alerts(state: State<'_, AppState>) -> CommandResult<Vec<TamperAlert>> {
    state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .tamper_alerts()
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_security_summary(state: State<'_, AppState>) -> CommandResult<SecuritySummary> {
    state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;

    let paths = state.store.paths();
    Ok(SecuritySummary {
        vault_root: paths.root.to_string_lossy().to_string(),
        manifest_path: paths.manifest.to_string_lossy().to_string(),
        user_vault_path: paths.user_vault.to_string_lossy().to_string(),
        admin_vault_path: paths.admin_vault.to_string_lossy().to_string(),
        chunks_dir: paths.chunks_dir.to_string_lossy().to_string(),
        encryption_summary: vec![
            "Passphrases are processed with Argon2id v19; passphrases themselves are never stored.".to_string(),
            "Bulk file payloads are single-file ZIP payloads encrypted as AES-256-GCM chunks.".to_string(),
            "Fast mode wraps the random file encryption key with the User Vault Key using AES-256-GCM.".to_string(),
            "Super Secure mode uses ML-KEM-1024 to encapsulate a shared secret, then wraps the file encryption key with AES-256-GCM under that shared secret.".to_string(),
            "BLAKE3 hashes verify source plaintext, payload chunks, and custody report exports.".to_string(),
        ],
        key_storage_summary: vec![
            "user.svault stores the user Argon2id salt/profile, the User Vault Key wrapped by the user-derived KEK, encrypted file metadata, and active user file-key wrappers or PQC seed wrappers.".to_string(),
            "admin.svault stores the admin Argon2id salt/profile, the Admin Vault Key wrapped by the admin-derived KEK, audit/recovery keys wrapped by the Admin Vault Key, recovery queue state, tamper alerts, and persistent lockdown state.".to_string(),
            "Pending-delete file keys are moved from active user access into recovery wrapping so Admin can recover or destroy them.".to_string(),
            "vault-data/chunks stores ciphertext only; it does not store plaintext names, plaintext bytes, or unwrapped keys.".to_string(),
            "signed-device-manifest.json stores drive identity, app binary hash, and optionally an Ed25519 production public key/signature.".to_string(),
        ],
        runtime_key_summary: vec![
            "On login, the backend derives a KEK from the passphrase, unwraps the role vault key, then keeps active keys only in Rust memory for the authenticated session.".to_string(),
            "KeyMaterial is zeroized on drop; logout, timeout, lockdown, and crypto-erase clear active runtime keys from AppState.".to_string(),
            "The frontend never receives passphrases after invocation, raw vault keys, file keys, PQC seeds, or decrypted metadata keys.".to_string(),
        ],
        manifest_summary: vec![
            "Unsigned development manifests have manifest_mode=UNSIGNED_DEVELOPMENT and no trusted Ed25519 key; this is for local rebuilds only.".to_string(),
            "Signed production manifests must include public_key_ed25519_b64 and signature_ed25519_b64; app hash or signature mismatch enters lockdown.".to_string(),
        ],
    })
}

#[tauri::command]
pub async fn admin_clear_lockdown(state: State<'_, AppState>) -> CommandResult<SessionStatus> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .clear_lockdown(&keys)
        .await
        .map_err(CommandError::from)?;
    Ok(state.clear_runtime_lockdown().await)
}

#[tauri::command]
pub async fn admin_export_custody_report(
    state: State<'_, AppState>,
    destination_dir: Option<String>,
) -> CommandResult<CustodyExportResult> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let destination = match destination_dir {
        Some(path) if !path.trim().is_empty() => {
            Some(path_from_external_input(&path).map_err(CommandError::from)?)
        }
        _ => None,
    };
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .export_custody_report(&keys, destination)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn admin_crypto_erase_vault(
    state: State<'_, AppState>,
    confirmation: String,
) -> CommandResult<CryptoEraseResult> {
    let keys = state
        .require_admin_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    let result = state
        .store
        .crypto_erase_vault(&keys, confirmation)
        .await
        .map_err(CommandError::from)?;
    state
        .enter_lockdown("vault cryptographic erase completed".to_string())
        .await;
    Ok(result)
}
