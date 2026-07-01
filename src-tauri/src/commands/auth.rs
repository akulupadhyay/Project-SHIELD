use crate::error::{CommandError, CommandResult, VaultError};
use crate::models::{Role, SessionStatus};
use crate::state::AppState;
use secrecy::SecretString;
use tauri::State;

#[tauri::command]
pub async fn initialize_vault(
    state: State<'_, AppState>,
    user_passphrase: String,
    admin_passphrase: String,
) -> CommandResult<SessionStatus> {
    validate_passphrase("user_passphrase", &user_passphrase)?;
    validate_passphrase("admin_passphrase", &admin_passphrase)?;

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
    if passphrase.is_empty() {
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

    if role == Role::User {
        if let Some(reason) = state.is_lockdown().await {
            return Err(CommandError::from(VaultError::Lockdown(reason)));
        }
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
        Role::Admin => match state
            .store
            .authenticate_admin(SecretString::new(passphrase))
            .await
        {
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
                Ok(state.start_admin_session(keys).await)
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
        },
    }
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> CommandResult<SessionStatus> {
    Ok(state.logout().await)
}

#[tauri::command]
pub async fn session_check(state: State<'_, AppState>) -> CommandResult<SessionStatus> {
    Ok(state.status().await)
}

fn validate_passphrase(label: &str, passphrase: &str) -> CommandResult<()> {
    if passphrase.len() < 12 {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} must be at least 12 characters"
        ))));
    }
    if passphrase.chars().all(char::is_whitespace) {
        return Err(CommandError::from(VaultError::InvalidInput(format!(
            "{label} cannot be blank"
        ))));
    }
    Ok(())
}
