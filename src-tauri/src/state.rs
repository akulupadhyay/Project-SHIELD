use crate::crypto::now_unix;
use crate::error::{VaultError, VaultResult};
use crate::models::{ManifestRuntimeStatus, Role, SessionStatus, Theme, UiMode};
use crate::vault::{UnlockedAdminKeys, UnlockedUserKeys, VaultStore};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

const USER_SESSION_SECONDS: i64 = 15 * 60;
const ADMIN_SESSION_SECONDS: i64 = 10 * 60;

pub struct AppState {
    pub store: VaultStore,
    pub runtime: RwLock<RuntimeState>,
    pub vault_lock: Mutex<()>,
}

impl AppState {
    pub fn new(
        store: VaultStore,
        initialized: bool,
        manifest_status: ManifestRuntimeStatus,
    ) -> Self {
        let storage_root = store.paths().root.to_string_lossy().to_string();
        Self {
            store,
            runtime: RwLock::new(RuntimeState::new(
                initialized,
                manifest_status,
                storage_root,
            )),
            vault_lock: Mutex::new(()),
        }
    }

    pub async fn status(&self) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.expire_if_needed();
        runtime.status()
    }

    pub async fn mark_initialized(&self) {
        let mut runtime = self.runtime.write().await;
        runtime.initialized = true;
        runtime.mode = UiMode::Locked;
    }

    pub async fn set_initialized(&self, initialized: bool) {
        let mut runtime = self.runtime.write().await;
        runtime.initialized = initialized;
        if !initialized {
            runtime.session = None;
            runtime.clear_keys();
            runtime.lockdown_reason = None;
            runtime.mode = UiMode::Uninitialized;
        } else if runtime.mode == UiMode::Uninitialized {
            runtime.mode = UiMode::Locked;
        }
    }

    pub async fn start_user_session(&self, keys: UnlockedUserKeys) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.clear_keys();
        runtime.session = Some(Session::new(Role::User, USER_SESSION_SECONDS));
        runtime.mode = UiMode::User;
        runtime.user_keys = Some(keys);
        runtime.status()
    }

    pub async fn start_admin_session(&self, keys: UnlockedAdminKeys) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.clear_keys();
        runtime.session = Some(Session::new(Role::Admin, ADMIN_SESSION_SECONDS));
        runtime.mode = UiMode::Admin;
        runtime.admin_keys = Some(keys);
        runtime.status()
    }

    pub async fn logout(&self) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.session = None;
        runtime.clear_keys();
        runtime.mode = if runtime.lockdown_reason.is_some() {
            UiMode::Lockdown
        } else if runtime.initialized {
            UiMode::Locked
        } else {
            UiMode::Uninitialized
        };
        runtime.status()
    }

    pub async fn enter_lockdown(&self, reason: String) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.session = None;
        runtime.clear_keys();
        runtime.lockdown_reason = Some(reason);
        runtime.mode = UiMode::Lockdown;
        runtime.status()
    }

    pub async fn clear_runtime_lockdown(&self) -> SessionStatus {
        let mut runtime = self.runtime.write().await;
        runtime.lockdown_reason = None;
        runtime.mode = if runtime.initialized {
            UiMode::Locked
        } else {
            UiMode::Uninitialized
        };
        runtime.status()
    }

    pub async fn require_user_keys(&self) -> VaultResult<UnlockedUserKeys> {
        let mut runtime = self.runtime.write().await;
        runtime.expire_if_needed();
        runtime.require_not_lockdown()?;

        match (&runtime.session, &runtime.user_keys) {
            (Some(session), Some(keys)) if session.role == Role::User => Ok(keys.clone()),
            (None, _) => Err(VaultError::SessionRequired),
            _ => Err(VaultError::PermissionDenied),
        }
    }

    pub async fn require_admin_keys(&self) -> VaultResult<UnlockedAdminKeys> {
        let mut runtime = self.runtime.write().await;
        runtime.expire_if_needed();

        match (&runtime.session, &runtime.admin_keys) {
            (Some(session), Some(keys)) if session.role == Role::Admin => Ok(keys.clone()),
            (None, _) => Err(VaultError::SessionRequired),
            _ => Err(VaultError::PermissionDenied),
        }
    }

    pub async fn is_lockdown(&self) -> Option<String> {
        let runtime = self.runtime.read().await;
        runtime.lockdown_reason.clone()
    }
}

pub struct RuntimeState {
    pub initialized: bool,
    pub mode: UiMode,
    pub session: Option<Session>,
    pub user_keys: Option<UnlockedUserKeys>,
    pub admin_keys: Option<UnlockedAdminKeys>,
    pub lockdown_reason: Option<String>,
    pub manifest_status: ManifestRuntimeStatus,
    pub storage_root: String,
}

impl RuntimeState {
    fn new(
        initialized: bool,
        manifest_status: ManifestRuntimeStatus,
        storage_root: String,
    ) -> Self {
        Self {
            initialized,
            mode: if initialized {
                UiMode::Locked
            } else {
                UiMode::Uninitialized
            },
            session: None,
            user_keys: None,
            admin_keys: None,
            lockdown_reason: None,
            manifest_status,
            storage_root,
        }
    }

    fn clear_keys(&mut self) {
        self.user_keys = None;
        self.admin_keys = None;
    }

    fn expire_if_needed(&mut self) {
        let expired = self
            .session
            .as_ref()
            .map(|session| session.expires_at_unix <= now_unix())
            .unwrap_or(false);

        if expired {
            self.session = None;
            self.clear_keys();
            if self.mode != UiMode::Lockdown {
                self.mode = if self.initialized {
                    UiMode::Locked
                } else {
                    UiMode::Uninitialized
                };
            }
        }
    }

    fn require_not_lockdown(&self) -> VaultResult<()> {
        if self.lockdown_reason.is_some() {
            return Err(VaultError::Lockdown(
                self.lockdown_reason
                    .clone()
                    .unwrap_or_else(|| "security event".to_string()),
            ));
        }
        Ok(())
    }

    fn status(&self) -> SessionStatus {
        let authenticated = self.session.is_some();
        let role = self.session.as_ref().map(|session| session.role);
        let session_id = self
            .session
            .as_ref()
            .map(|session| session.session_id.clone());
        let issued_at_unix = self.session.as_ref().map(|session| session.issued_at_unix);
        let expires_at_unix = self.session.as_ref().map(|session| session.expires_at_unix);
        let mode = if authenticated {
            match role {
                Some(Role::User) if self.lockdown_reason.is_none() => UiMode::User,
                Some(Role::User) => UiMode::Lockdown,
                Some(Role::Admin) => UiMode::Admin,
                None => self.mode,
            }
        } else if self.lockdown_reason.is_some() {
            UiMode::Lockdown
        } else {
            self.mode
        };

        SessionStatus {
            initialized: self.initialized,
            authenticated,
            mode,
            theme: theme_for_mode(mode),
            role,
            session_id,
            issued_at_unix,
            allowed_actions: allowed_actions(mode),
            expires_at_unix,
            lockdown_reason: self.lockdown_reason.clone(),
            manifest_status: self.manifest_status.clone(),
            storage_root: self.storage_root.clone(),
            admin_recovery_key_one_time: None,
        }
    }
}

pub struct Session {
    pub session_id: String,
    pub role: Role,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl Session {
    fn new(role: Role, ttl_seconds: i64) -> Self {
        let issued_at_unix = now_unix();
        Self {
            session_id: Uuid::new_v4().to_string(),
            role,
            issued_at_unix,
            expires_at_unix: issued_at_unix + ttl_seconds,
        }
    }
}

fn theme_for_mode(mode: UiMode) -> Theme {
    match mode {
        UiMode::User => Theme::Green,
        UiMode::Admin => Theme::Blue,
        UiMode::Lockdown => Theme::DarkRed,
        UiMode::Uninitialized | UiMode::Locked => Theme::Neutral,
    }
}

fn allowed_actions(mode: UiMode) -> Vec<String> {
    let actions: &[&str] = match mode {
        UiMode::User => &["list", "upload", "download", "delete_request", "logout"],
        UiMode::Admin => &[
            "view_audit",
            "view_audit_tables",
            "export_audit_logs",
            "view_recovery",
            "recover_file",
            "destroy_file",
            "reset_user_password",
            "view_tamper_alerts",
            "clear_lockdown",
            "export_custody_report",
            "crypto_erase_vault",
            "logout",
        ],
        UiMode::Lockdown => &["clear_lockdown_with_recovery_key"],
        UiMode::Uninitialized => &["initialize_vault"],
        UiMode::Locked => &["login", "reset_admin_password_with_recovery_key"],
    };
    actions.iter().map(|action| (*action).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_key;
    use crate::models::ManifestRuntimeStatus;
    use crate::vault::{UnlockedAdminKeys, VaultStore};

    #[tokio::test]
    async fn lockdown_survives_admin_session_until_explicitly_cleared() {
        let root =
            std::env::temp_dir().join(format!("secure-vault-state-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::from_root(&root).expect("state test store");
        let state = AppState::new(
            store,
            true,
            ManifestRuntimeStatus {
                status: "TEST".to_string(),
                drive_id: Some("test-drive".to_string()),
                message: "test".to_string(),
            },
        );

        let lockdown = state.enter_lockdown("test lockdown".to_string()).await;
        assert_eq!(lockdown.mode, UiMode::Lockdown);

        let admin = state
            .start_admin_session(UnlockedAdminKeys {
                admin_vault_key: random_key(),
                audit_key: random_key(),
                recovery_key: random_key(),
                user_vault_key: random_key(),
            })
            .await;
        assert_eq!(admin.mode, UiMode::Admin);
        assert_eq!(admin.lockdown_reason.as_deref(), Some("test lockdown"));

        let after_logout = state.logout().await;
        assert_eq!(after_logout.mode, UiMode::Lockdown);
        assert_eq!(
            after_logout.lockdown_reason.as_deref(),
            Some("test lockdown")
        );

        let cleared = state.clear_runtime_lockdown().await;
        assert_eq!(cleared.mode, UiMode::Locked);
        assert!(cleared.lockdown_reason.is_none());

        let _ = std::fs::remove_dir_all(root);
    }
}
