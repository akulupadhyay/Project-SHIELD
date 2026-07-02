use crate::error::{CommandError, CommandResult, VaultError};
use crate::models::{Role, SessionStatus};
use crate::state::AppState;
use secrecy::SecretString;
use tauri::State;

const MAX_SECRET_INPUT_CHARS: usize = 4096;

#[tauri::command]
pub async fn initialize_vault(
    state: State<'_, AppState>,
    user_passphrase: String,
    admin_passphrase: String,
) -> CommandResult<SessionStatus> {
    validate_passphrase("user_passphrase", &user_passphrase)?;
    validate_passphrase("admin_passphrase", &admin_passphrase)?;
    if user_passphrase == admin_passphrase {
        return Err(CommandError::from(VaultError::InvalidInput(
            "user_passphrase and admin_passphrase must be different".to_string(),
        )));
    }

    let _guard = state.vault_lock.lock().await;
    state
        .store
        .initialize(
            SecretString::new(user_passphrase),
            SecretString::new(admin_passphrase),
        )
        .await
        .map_err(CommandError::from)?;
    state.mark_initialized().await;
    Ok(state.status().await)
}

#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    role: Role,
    passphrase: String,
) -> CommandResult<SessionStatus> {
    validate_secret_transport("passphrase", &passphrase)?;
    if passphrase.trim().is_empty() {
        return Err(CommandError::from(VaultError::AuthenticationFailed));
    }

    if !state
        .store
        .is_initialized()
        .await
        .map_err(CommandError::from)?
    {
        return Err(CommandError::from(VaultError::NotInitialized));
    }

    if let Some(reason) = state.is_lockdown().await {
        return Err(CommandError::from(VaultError::Lockdown(reason)));
    }

    let _guard = state.vault_lock.lock().await;
    match role {
        Role::User => match state
            .store
            .authenticate_user(SecretString::new(passphrase))
            .await
        {
            Ok(keys) => {
                state
                    .store
                    .record_auth_event(Role::User, "successful", "credentials_verified")
                    .await
                    .map_err(CommandError::from)?;
                state
                    .store
                    .record_successful_user_login(&keys)
                    .await
                    .map_err(CommandError::from)?;
                Ok(state.start_user_session(keys).await)
            }
            Err(error) => {
                state
                    .store
                    .record_auth_event(Role::User, "failed", "authentication_failed")
                    .await
                    .map_err(CommandError::from)?;
                Err(CommandError::from(error))
            }
        },
        Role::Admin => {
            let admin_secret = SecretString::new(passphrase);
            match state.store.authenticate_admin(admin_secret.clone()).await {
                Ok(keys) => {
                    state
                        .store
                        .reset_failed_admin_logins(&keys)
                        .await
                        .map_err(CommandError::from)?;
                    state
                        .store
                        .record_auth_event(Role::Admin, "successful", "credentials_verified")
                        .await
                        .map_err(CommandError::from)?;
                    let recovery_key = state
                        .store
                        .ensure_admin_recovery_key(&keys, &admin_secret)
                        .await
                        .map_err(CommandError::from)?;
                    let mut session = state.start_admin_session(keys).await;
                    session.admin_recovery_key_one_time = recovery_key;
                    Ok(session)
                }
                Err(error) => {
                    let lockdown = state
                        .store
                        .record_failed_admin_login()
                        .await
                        .map_err(CommandError::from)?;
                    if let Some(reason) = lockdown {
                        state.enter_lockdown(reason.clone()).await;
                        return Err(CommandError::from(VaultError::Lockdown(reason)));
                    }
                    Err(CommandError::from(error))
                }
            }
        }
    }
}

#[tauri::command]
pub async fn reset_admin_password_with_recovery_key(
    state: State<'_, AppState>,
    recovery_key: String,
    new_admin_passphrase: String,
) -> CommandResult<SessionStatus> {
    validate_recovery_key("recovery_key", &recovery_key)?;
    validate_passphrase("new_admin_passphrase", &new_admin_passphrase)?;

    let _guard = state.vault_lock.lock().await;
    state
        .store
        .reset_admin_password_with_recovery_key(
            SecretString::new(recovery_key.trim().to_string()),
            SecretString::new(new_admin_passphrase),
        )
        .await
        .map_err(CommandError::from)?;
    Ok(state.status().await)
}

#[tauri::command]
pub async fn clear_lockdown_with_recovery_key(
    state: State<'_, AppState>,
    recovery_key: String,
) -> CommandResult<SessionStatus> {
    validate_recovery_key("recovery_key", &recovery_key)?;

    let _guard = state.vault_lock.lock().await;
    let initialized = state
        .store
        .clear_lockdown_with_recovery_key(SecretString::new(recovery_key.trim().to_string()))
        .await
        .map_err(CommandError::from)?;
    state.set_initialized(initialized).await;
    Ok(state.clear_runtime_lockdown().await)
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> CommandResult<SessionStatus> {
    Ok(state.logout().await)
}

#[tauri::command]
pub async fn session_check(state: State<'_, AppState>) -> CommandResult<SessionStatus> {
    Ok(state.status().await)
}

pub(crate) fn validate_passphrase(label: &str, passphrase: &str) -> CommandResult<()> {
    validate_secret_transport(label, passphrase)?;
    if passphrase.trim().chars().count() < 12 {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} must be at least 12 characters"
        ))));
    }
    if passphrase.chars().all(char::is_whitespace) {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} cannot be blank"
        ))));
    }
    if is_repetitive_secret(passphrase) {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} must not be a repetitive pattern"
        ))));
    }
    Ok(())
}

fn validate_recovery_key(label: &str, value: &str) -> CommandResult<()> {
    validate_secret_transport(label, value)?;
    let trimmed = value.trim();
    if !trimmed.starts_with("SHIELD-") || trimmed.len() < 80 {
        return Err(CommandError::from(VaultError::AuthenticationFailed));
    }
    Ok(())
}

fn validate_secret_transport(label: &str, value: &str) -> CommandResult<()> {
    if value.chars().count() > MAX_SECRET_INPUT_CHARS {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} is too long to process safely"
        ))));
    }
    if value.chars().any(|ch| ch == '\0') {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} must not contain NUL bytes"
        ))));
    }
    if value.chars().any(char::is_control) {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} must not contain control characters"
        ))));
    }
    Ok(())
}

fn is_repetitive_secret(value: &str) -> bool {
    let chars: Vec<char> = value.trim().chars().collect();
    if chars.len() < 2 {
        return true;
    }
    if chars.windows(2).all(|pair| pair[0] == pair[1]) {
        return true;
    }
    let max_pattern = 6.min(chars.len() / 2);
    for pattern_len in 1..=max_pattern {
        if chars.len() % pattern_len != 0 {
            continue;
        }
        let pattern = &chars[..pattern_len];
        if chars.chunks(pattern_len).all(|chunk| chunk == pattern) {
            return true;
        }
    }
    false
}
