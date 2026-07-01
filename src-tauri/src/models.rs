use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn audit_actor(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Admin => "ADMIN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UiMode {
    Uninitialized,
    Locked,
    User,
    Admin,
    Lockdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Theme {
    Neutral,
    Green,
    Blue,
    DarkRed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileState {
    Active,
    PendingDelete,
    CryptoErased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UploadSecurityMode {
    Fast,
    SuperSecure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadFormat {
    Raw,
    ZipStoredV1,
}

impl Default for PayloadFormat {
    fn default() -> Self {
        Self::Raw
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileKeyProtection {
    Aes256GcmKeyWrap,
    MlKem1024Aes256GcmKeyWrap,
}

impl Default for FileKeyProtection {
    fn default() -> Self {
        Self::Aes256GcmKeyWrap
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub initialized: bool,
    pub authenticated: bool,
    pub mode: UiMode,
    pub theme: Theme,
    pub role: Option<Role>,
    pub session_id: Option<String>,
    pub issued_at_unix: Option<i64>,
    pub allowed_actions: Vec<String>,
    pub expires_at_unix: Option<i64>,
    pub lockdown_reason: Option<String>,
    pub manifest_status: ManifestRuntimeStatus,
    pub storage_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_recovery_key_one_time: Option<AdminRecoveryKeyPresentation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRuntimeStatus {
    pub status: String,
    pub drive_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEnvelope {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfProfile {
    pub algorithm: String,
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEnvelope {
    pub kdf: KdfProfile,
    pub wrapped_vault_key: AeadEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserVaultDisk {
    pub version: u32,
    pub drive_id: String,
    pub user_credential: CredentialEnvelope,
    pub audit_key_wrapped_by_user_vault: AeadEnvelope,
    pub recovery_key_wrapped_by_user_vault: AeadEnvelope,
    pub files: Vec<UserFileRecord>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminVaultDisk {
    pub version: u32,
    pub drive_id: String,
    pub admin_credential: CredentialEnvelope,
    pub audit_key_wrapped_by_admin_vault: AeadEnvelope,
    pub recovery_key_wrapped_by_admin_vault: AeadEnvelope,
    pub user_vault_key_wrapped_by_recovery_key: AeadEnvelope,
    pub failed_admin_attempts: u32,
    pub lockdown: Option<LockdownRecord>,
    pub audit_log: AuditLogDisk,
    pub recovery_queue: Vec<RecoveryRecord>,
    pub tamper_alerts: Vec<TamperAlert>,
    #[serde(default)]
    pub auth_events: Vec<AuthEventRecord>,
    #[serde(default)]
    pub admin_recovery: Option<AdminRecoveryCredential>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecoveryCredential {
    pub key_id: String,
    pub created_at_unix: i64,
    pub kdf: KdfProfile,
    pub admin_vault_key_wrapped_by_recovery_key: AeadEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecoveryKeyPresentation {
    pub key_id: String,
    pub created_at_unix: i64,
    pub recovery_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFileRecord {
    pub file_id: String,
    pub state: FileState,
    pub metadata_encrypted_by_user_vault: AeadEnvelope,
    pub user_fek: Option<AeadEnvelope>,
    pub recovery_fek: Option<AeadEnvelope>,
    #[serde(default)]
    pub pqc: Option<PqcFileKeyEnvelope>,
    pub chunks: Vec<ChunkRecord>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcFileKeyEnvelope {
    pub algorithm: String,
    pub kem_ciphertext_b64: String,
    pub fek_wrapped_by_pqc_shared_key: AeadEnvelope,
    pub user_decapsulation_seed_wrapped_by_user_vault: Option<AeadEnvelope>,
    pub recovery_decapsulation_seed_wrapped_by_recovery_key: Option<AeadEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub index: u64,
    pub relative_path: String,
    pub nonce_b64: String,
    pub original_len: u64,
    pub stored_plain_len: u64,
    pub ciphertext_len: u64,
    pub compressed: bool,
    pub chunk_blake3_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub original_name: String,
    pub original_size: u64,
    pub original_blake3_b64: String,
    pub upload_mode: UploadSecurityMode,
    #[serde(default)]
    pub payload_format: PayloadFormat,
    #[serde(default)]
    pub key_protection: FileKeyProtection,
    #[serde(default)]
    pub payload_size: u64,
    pub chunk_count: u64,
    pub uploaded_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileListEntry {
    pub file_id: String,
    pub original_name: String,
    pub original_size: u64,
    pub original_blake3_b64: String,
    pub upload_mode: UploadSecurityMode,
    pub payload_format: PayloadFormat,
    pub key_protection: FileKeyProtection,
    pub chunk_count: u64,
    pub uploaded_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadProgress {
    pub operation_id: String,
    pub stage: String,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percent: u8,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub file_id: String,
    pub output_path: String,
    pub bytes_written: u64,
    pub original_blake3_b64: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequestResult {
    pub file_id: String,
    pub state: FileState,
    pub queued_for_admin_recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub file_id: String,
    pub requested_by: String,
    pub requested_at_unix: i64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryView {
    pub file_id: String,
    pub requested_by: String,
    pub requested_at_unix: i64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogDisk {
    pub sequence: u64,
    pub last_hash_b64: String,
    pub entries: Vec<AuditEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub sequence: u64,
    pub timestamp_unix: i64,
    pub previous_hash_b64: String,
    pub record_hash_b64: String,
    pub encrypted_record: AeadEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPlainRecord {
    pub sequence: u64,
    pub timestamp_unix: i64,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditView {
    pub sequence: u64,
    pub timestamp_unix: i64,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub details: serde_json::Value,
    pub record_hash_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostFingerprint {
    pub hostname: String,
    pub username_hash_blake3_b64: String,
    pub architecture: String,
    pub machine_family: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEventRecord {
    pub sequence: u64,
    pub role: Role,
    pub timestamp_unix: i64,
    pub status: String,
    pub reason_code: String,
    pub host: HostFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTables {
    pub login_logs: Vec<LoginLogRow>,
    pub host_fingerprints: Vec<HostFingerprintLogRow>,
    pub operation_logs: Vec<OperationLogRow>,
    pub raw_log_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginLogRow {
    pub serial_number: u64,
    pub username: String,
    pub timestamp_unix: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFingerprintLogRow {
    pub serial_number: u64,
    pub hostname: String,
    pub host_machine_info: String,
    pub os: String,
    pub timestamp_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationLogRow {
    pub serial_number: u64,
    pub operation_done: String,
    pub timestamp_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportResult {
    pub category: String,
    pub output_path: String,
    pub report_blake3_b64: String,
    pub row_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlert {
    pub alert_id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub created_at_unix: i64,
    pub cleared_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownRecord {
    pub reason: String,
    pub triggered_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyReport {
    pub drive_id: String,
    pub exported_at_unix: i64,
    pub audit_entries: Vec<AuditView>,
    pub recovery_queue: Vec<RecoveryView>,
    pub tamper_alerts: Vec<TamperAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyExportResult {
    pub output_path: String,
    pub report_blake3_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub vault_root: String,
    pub manifest_path: String,
    pub user_vault_path: String,
    pub admin_vault_path: String,
    pub chunks_dir: String,
    pub encryption_summary: Vec<String>,
    pub key_storage_summary: Vec<String>,
    pub runtime_key_summary: Vec<String>,
    pub manifest_summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEraseResult {
    pub destroyed_file_count: usize,
    pub lockdown: bool,
}
