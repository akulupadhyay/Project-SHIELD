use serde::Serialize;
use thiserror::Error;

pub type VaultResult<T> = Result<T, VaultError>;
pub type CommandResult<T> = Result<T, CommandError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("session is missing or expired")]
    SessionRequired,
    #[error("the current session does not have permission for this operation")]
    PermissionDenied,
    #[error("vault is in lockdown mode: {0}")]
    Lockdown(String),
    #[error("file was not found")]
    FileNotFound,
    #[error("file is not active")]
    FileNotActive,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("manifest verification failed: {0}")]
    Manifest(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl From<VaultError> for CommandError {
    fn from(error: VaultError) -> Self {
        let code = match &error {
            VaultError::AlreadyInitialized => "already_initialized",
            VaultError::NotInitialized => "not_initialized",
            VaultError::AuthenticationFailed => "authentication_failed",
            VaultError::SessionRequired => "session_required",
            VaultError::PermissionDenied => "permission_denied",
            VaultError::Lockdown(_) => "lockdown",
            VaultError::FileNotFound => "file_not_found",
            VaultError::FileNotActive => "file_not_active",
            VaultError::InvalidInput(_) => "invalid_input",
            VaultError::Integrity(_) => "integrity_error",
            VaultError::Crypto(_) => "crypto_error",
            VaultError::Manifest(_) => "manifest_error",
            VaultError::Io(_) => "io_error",
            VaultError::Serialization(_) => "serialization_error",
        };

        Self {
            code,
            message: error.to_string(),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

impl From<base64::DecodeError> for VaultError {
    fn from(error: base64::DecodeError) -> Self {
        Self::Serialization(error.to_string())
    }
}
