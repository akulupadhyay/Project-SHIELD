use crate::archive::{build_zip_stored_plan, Crc32, ZipStoredDecoder};
use crate::audit::{
    add_tamper_alert, append_audit_record, current_host_fingerprint, decrypt_audit_log,
    empty_audit_log, host_observed_details,
};
use crate::crypto::{
    b64_decode, b64_encode, blake3_b64, constant_time_eq, decompress_chunk, decrypt_bytes,
    decrypt_chunk, decrypt_json, default_kdf_profile, derive_key, encrypt_bytes, encrypt_chunk,
    encrypt_json, now_unix, random_key, unwrap_key, wrap_key, KeyMaterial, DEFAULT_CHUNK_SIZE,
};
use crate::error::{VaultError, VaultResult};
use crate::manifest::manifest_path_for_root;
use crate::models::{
    AdminVaultDisk, AeadEnvelope, AuditExportResult, AuditTables, AuditView, AuthEventRecord,
    ChunkRecord, CredentialEnvelope, CryptoEraseResult, CustodyExportResult, CustodyReport,
    DeleteRequestResult, DownloadResult, FileKeyProtection, FileListEntry, FileMetadata, FileState,
    HostFingerprint, HostFingerprintLogRow, LockdownRecord, LoginLogRow, OperationLogRow,
    PayloadFormat, PqcFileKeyEnvelope, RecoveryRecord, RecoveryView, Role, TamperAlert,
    UploadProgress, UploadSecurityMode, UserFileRecord, UserVaultDisk,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_1024::{Ciphertext as MlKem1024Ciphertext, DecapsulationKey as MlKem1024PrivateKey},
    MlKem1024, Seed,
};
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use zeroize::Zeroize;

const USER_VAULT_KEY_BY_USER_KEK: &str = "secure-vault:v1:user-vault-key:by-user-kek";
const ADMIN_VAULT_KEY_BY_ADMIN_KEK: &str = "secure-vault:v1:admin-vault-key:by-admin-kek";
const AUDIT_KEY_BY_USER_VAULT: &str = "secure-vault:v1:audit-key:by-user-vault";
const AUDIT_KEY_BY_ADMIN_VAULT: &str = "secure-vault:v1:audit-key:by-admin-vault";
const RECOVERY_KEY_BY_USER_VAULT: &str = "secure-vault:v1:recovery-key:by-user-vault";
const RECOVERY_KEY_BY_ADMIN_VAULT: &str = "secure-vault:v1:recovery-key:by-admin-vault";
const USER_VAULT_KEY_BY_RECOVERY_KEY: &str = "secure-vault:v1:user-vault-key:by-recovery-key";
const FILE_KEY_BY_USER_VAULT: &str = "secure-vault:v1:file-key:by-user-vault";
const FILE_KEY_BY_RECOVERY_KEY: &str = "secure-vault:v1:file-key:by-recovery-key";
const PQC_FILE_KEY_ALGORITHM: &str = "ML-KEM-1024+AES-256-GCM";
const PQC_FILE_KEY_BY_SHARED_SECRET: &str = "secure-vault:v1:file-key:by-ml-kem-1024";
const ADMIN_FAILED_LOGIN_LOCKDOWN_THRESHOLD: u32 = 5;

#[derive(Clone)]
pub struct UnlockedUserKeys {
    pub user_vault_key: KeyMaterial,
    pub audit_key: KeyMaterial,
    pub recovery_key: KeyMaterial,
}

#[derive(Clone)]
pub struct UnlockedAdminKeys {
    pub audit_key: KeyMaterial,
    pub recovery_key: KeyMaterial,
    pub user_vault_key: KeyMaterial,
}

#[derive(Clone)]
pub struct VaultStore {
    paths: VaultPaths,
}

#[derive(Clone)]
pub struct VaultPaths {
    pub root: PathBuf,
    pub data_dir: PathBuf,
    pub chunks_dir: PathBuf,
    pub user_vault: PathBuf,
    pub admin_vault: PathBuf,
    pub manifest: PathBuf,
}

impl VaultStore {
    pub fn portable() -> VaultResult<Self> {
        Self::from_root(resolve_portable_root()?)
    }

    pub fn from_root(root: impl Into<PathBuf>) -> VaultResult<Self> {
        let root = absolutize_path(root.into())?;
        let data_dir = root.join("vault-data");
        let chunks_dir = data_dir.join("chunks");
        Ok(Self {
            paths: VaultPaths {
                manifest: manifest_path_for_root(&root),
                user_vault: data_dir.join("user.svault"),
                admin_vault: data_dir.join("admin.svault"),
                root,
                data_dir,
                chunks_dir,
            },
        })
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub async fn ensure_dirs(&self) -> VaultResult<()> {
        fs::create_dir_all(&self.paths.data_dir).await?;
        fs::create_dir_all(&self.paths.chunks_dir).await?;
        Ok(())
    }

    pub async fn is_initialized(&self) -> VaultResult<bool> {
        Ok(fs::try_exists(&self.paths.user_vault).await?
            && fs::try_exists(&self.paths.admin_vault).await?)
    }

    pub async fn initialize(
        &self,
        user_passphrase: SecretString,
        admin_passphrase: SecretString,
    ) -> VaultResult<()> {
        self.ensure_dirs().await?;
        if self.is_initialized().await? {
            return Err(VaultError::AlreadyInitialized);
        }

        let drive_id = load_or_create_drive_id(&self.paths.manifest)?;
        let created_at_unix = now_unix();
        let user_vault_key = random_key();
        let admin_vault_key = random_key();
        let audit_key = random_key();
        let recovery_key = random_key();

        let user_kdf = default_kdf_profile();
        let admin_kdf = default_kdf_profile();
        let user_kek = derive_key(&user_passphrase, &user_kdf)?;
        let admin_kek = derive_key(&admin_passphrase, &admin_kdf)?;

        let user_credential = CredentialEnvelope {
            kdf: user_kdf,
            wrapped_vault_key: wrap_key(&user_kek, &user_vault_key, USER_VAULT_KEY_BY_USER_KEK)?,
        };
        let admin_credential = CredentialEnvelope {
            kdf: admin_kdf,
            wrapped_vault_key: wrap_key(
                &admin_kek,
                &admin_vault_key,
                ADMIN_VAULT_KEY_BY_ADMIN_KEK,
            )?,
        };

        let user_vault = UserVaultDisk {
            version: 1,
            drive_id: drive_id.clone(),
            user_credential,
            audit_key_wrapped_by_user_vault: wrap_key(
                &user_vault_key,
                &audit_key,
                AUDIT_KEY_BY_USER_VAULT,
            )?,
            recovery_key_wrapped_by_user_vault: wrap_key(
                &user_vault_key,
                &recovery_key,
                RECOVERY_KEY_BY_USER_VAULT,
            )?,
            files: Vec::new(),
            created_at_unix,
            updated_at_unix: created_at_unix,
        };

        let mut admin_vault = AdminVaultDisk {
            version: 1,
            drive_id,
            admin_credential,
            audit_key_wrapped_by_admin_vault: wrap_key(
                &admin_vault_key,
                &audit_key,
                AUDIT_KEY_BY_ADMIN_VAULT,
            )?,
            recovery_key_wrapped_by_admin_vault: wrap_key(
                &admin_vault_key,
                &recovery_key,
                RECOVERY_KEY_BY_ADMIN_VAULT,
            )?,
            user_vault_key_wrapped_by_recovery_key: wrap_key(
                &recovery_key,
                &user_vault_key,
                USER_VAULT_KEY_BY_RECOVERY_KEY,
            )?,
            failed_admin_attempts: 0,
            lockdown: None,
            audit_log: empty_audit_log(),
            recovery_queue: Vec::new(),
            tamper_alerts: Vec::new(),
            auth_events: Vec::new(),
            created_at_unix,
            updated_at_unix: created_at_unix,
        };

        append_audit_record(
            &mut admin_vault,
            &audit_key,
            "SYSTEM",
            "vault_initialized",
            "SUCCESS",
            json!({ "version": 1 }),
        )?;

        write_json_atomic(&self.paths.user_vault, &user_vault).await?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;
        Ok(())
    }

    pub async fn authenticate_user(
        &self,
        passphrase: SecretString,
    ) -> VaultResult<UnlockedUserKeys> {
        let user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let user_kek = derive_key(&passphrase, &user_vault.user_credential.kdf)?;
        let user_vault_key = unwrap_key(
            &user_kek,
            &user_vault.user_credential.wrapped_vault_key,
            USER_VAULT_KEY_BY_USER_KEK,
        )?;
        let audit_key = unwrap_key(
            &user_vault_key,
            &user_vault.audit_key_wrapped_by_user_vault,
            AUDIT_KEY_BY_USER_VAULT,
        )?;
        let recovery_key = unwrap_key(
            &user_vault_key,
            &user_vault.recovery_key_wrapped_by_user_vault,
            RECOVERY_KEY_BY_USER_VAULT,
        )?;

        Ok(UnlockedUserKeys {
            user_vault_key,
            audit_key,
            recovery_key,
        })
    }

    pub async fn authenticate_admin(
        &self,
        passphrase: SecretString,
    ) -> VaultResult<UnlockedAdminKeys> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let admin_kek = derive_key(&passphrase, &admin_vault.admin_credential.kdf)?;
        let admin_vault_key = unwrap_key(
            &admin_kek,
            &admin_vault.admin_credential.wrapped_vault_key,
            ADMIN_VAULT_KEY_BY_ADMIN_KEK,
        )?;
        let audit_key = unwrap_key(
            &admin_vault_key,
            &admin_vault.audit_key_wrapped_by_admin_vault,
            AUDIT_KEY_BY_ADMIN_VAULT,
        )?;
        let recovery_key = unwrap_key(
            &admin_vault_key,
            &admin_vault.recovery_key_wrapped_by_admin_vault,
            RECOVERY_KEY_BY_ADMIN_VAULT,
        )?;
        let user_vault_key = unwrap_key(
            &recovery_key,
            &admin_vault.user_vault_key_wrapped_by_recovery_key,
            USER_VAULT_KEY_BY_RECOVERY_KEY,
        )?;

        Ok(UnlockedAdminKeys {
            audit_key,
            recovery_key,
            user_vault_key,
        })
    }

    pub async fn record_auth_event(
        &self,
        role: Role,
        status: &str,
        reason_code: &str,
    ) -> VaultResult<()> {
        if !self.is_initialized().await? {
            return Ok(());
        }

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        push_auth_event(&mut admin_vault, role, status, reason_code);
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await
    }

    pub async fn record_successful_user_login(&self, keys: &UnlockedUserKeys) -> VaultResult<()> {
        self.append_audit_with_key(
            &keys.audit_key,
            Role::User.audit_actor(),
            "user_login",
            "SUCCESS",
            json!({ "host": host_observed_details() }),
        )
        .await?;
        Ok(())
    }

    pub async fn reset_failed_admin_logins(&self, keys: &UnlockedAdminKeys) -> VaultResult<()> {
        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        admin_vault.failed_admin_attempts = 0;
        append_audit_record(
            &mut admin_vault,
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "admin_login",
            "SUCCESS",
            json!({
                "failed_admin_attempts_reset": true,
                "host": host_observed_details()
            }),
        )?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await
    }

    pub async fn record_failed_admin_login(&self) -> VaultResult<Option<String>> {
        if !self.is_initialized().await? {
            return Ok(None);
        }

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        admin_vault.failed_admin_attempts = admin_vault.failed_admin_attempts.saturating_add(1);
        push_auth_event(
            &mut admin_vault,
            Role::Admin,
            "failed",
            "authentication_failed",
        );
        let mut reason = None;

        if admin_vault.failed_admin_attempts >= ADMIN_FAILED_LOGIN_LOCKDOWN_THRESHOLD {
            let lockdown_reason = format!(
                "{} failed admin login attempts",
                admin_vault.failed_admin_attempts
            );
            admin_vault.lockdown = Some(LockdownRecord {
                reason: lockdown_reason.clone(),
                triggered_at_unix: now_unix(),
            });
            add_tamper_alert(
                &mut admin_vault,
                "failed_admin_threshold",
                "HIGH",
                &lockdown_reason,
            );
            reason = Some(lockdown_reason);
        }

        admin_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;
        Ok(reason)
    }

    pub async fn persistent_lockdown_reason(&self) -> VaultResult<Option<String>> {
        if !self.is_initialized().await? {
            return Ok(None);
        }
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        Ok(admin_vault.lockdown.map(|record| record.reason))
    }

    pub async fn list_files(&self, keys: &UnlockedUserKeys) -> VaultResult<Vec<FileListEntry>> {
        let user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let mut files = Vec::new();
        for record in user_vault
            .files
            .iter()
            .filter(|record| record.state == FileState::Active)
        {
            let metadata = decrypt_file_metadata(&keys.user_vault_key, record)?;
            files.push(FileListEntry {
                file_id: record.file_id.clone(),
                original_name: metadata.original_name,
                original_size: metadata.original_size,
                original_blake3_b64: metadata.original_blake3_b64,
                upload_mode: metadata.upload_mode,
                payload_format: metadata.payload_format,
                key_protection: metadata.key_protection,
                chunk_count: metadata.chunk_count,
                uploaded_at_unix: metadata.uploaded_at_unix,
            });
        }
        Ok(files)
    }

    #[allow(dead_code)]
    pub async fn upload_file(
        &self,
        keys: &UnlockedUserKeys,
        source_path: PathBuf,
        mode: UploadSecurityMode,
    ) -> VaultResult<FileListEntry> {
        self.upload_file_with_progress(keys, source_path, mode, String::new(), |_| {})
            .await
    }

    pub async fn upload_file_with_progress<F>(
        &self,
        keys: &UnlockedUserKeys,
        source_path: PathBuf,
        mode: UploadSecurityMode,
        operation_id: String,
        progress: F,
    ) -> VaultResult<FileListEntry>
    where
        F: Fn(UploadProgress) + Send + Sync,
    {
        let metadata = fs::metadata(&source_path).await?;
        if !metadata.is_file() {
            return Err(VaultError::InvalidInput(
                "upload source must be a file".to_string(),
            ));
        }

        let original_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(sanitize_file_name)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| VaultError::InvalidInput("source file has no valid name".to_string()))?;

        emit_upload_progress(
            &progress,
            &operation_id,
            "starting",
            0,
            metadata.len(),
            0,
            "Preparing upload",
        );
        self.ensure_dirs().await?;
        let file_id = Uuid::new_v4().to_string();
        let staging_dir = self.paths.chunks_dir.join(".staging").join(&file_id);
        let final_dir = self.paths.chunks_dir.join(&file_id);
        fs::create_dir_all(&staging_dir).await?;

        let file_key = random_key();
        let source_profile =
            inspect_source_file(&source_path, metadata.len(), &operation_id, &progress).await?;
        emit_upload_progress(
            &progress,
            &operation_id,
            "wrapping_key",
            metadata.len(),
            metadata.len(),
            20,
            "Wrapping file key",
        );
        let zip_plan = build_zip_stored_plan(&original_name, metadata.len(), source_profile.crc32)?;
        let (user_fek, pqc) = wrap_file_key_for_upload(keys, &file_key, &file_id, mode)?;
        let key_protection = key_protection_for_mode(mode);
        let mut chunk_writer = EncryptedChunkWriter::new(
            &file_key,
            &file_id,
            &self.paths.chunks_dir,
            staging_dir.clone(),
            chunk_suffix_for_mode(mode),
        );

        emit_upload_progress(
            &progress,
            &operation_id,
            "encrypting",
            0,
            metadata.len(),
            25,
            "Writing ZIP header and starting chunk encryption",
        );
        chunk_writer.push(&zip_plan.local_header).await?;
        let mut file = fs::File::open(&source_path).await?;
        let mut buffer = vec![0u8; DEFAULT_CHUNK_SIZE];
        let mut bytes_encrypted = 0u64;
        loop {
            let read_len = file.read(&mut buffer).await?;
            if read_len == 0 {
                break;
            }
            chunk_writer.push(&buffer[..read_len]).await?;
            bytes_encrypted = bytes_encrypted.saturating_add(read_len as u64);
            emit_upload_progress(
                &progress,
                &operation_id,
                "encrypting",
                bytes_encrypted,
                metadata.len(),
                scaled_percent(25, 90, bytes_encrypted, metadata.len()),
                "Encrypting ZIP payload into AES-256-GCM chunks",
            );
        }
        chunk_writer
            .push(&zip_plan.central_directory_and_eocd)
            .await?;
        emit_upload_progress(
            &progress,
            &operation_id,
            "committing",
            metadata.len(),
            metadata.len(),
            92,
            "Finalizing encrypted chunks",
        );
        let mut chunks = chunk_writer.finalize().await?;

        if fs::try_exists(&final_dir).await? {
            fs::remove_dir_all(&final_dir).await?;
        }
        fs::rename(&staging_dir, &final_dir).await?;
        for chunk in &mut chunks {
            let file_name = Path::new(&chunk.relative_path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| VaultError::InvalidInput("invalid staged chunk name".to_string()))?;
            chunk.relative_path = format!("{file_id}/{file_name}");
        }

        let chunk_count = chunks.len() as u64;
        let original_hash_b64 = source_profile.blake3_b64;
        let uploaded_at_unix = now_unix();
        let metadata_plain = FileMetadata {
            original_name: original_name.clone(),
            original_size: metadata.len(),
            original_blake3_b64: original_hash_b64.clone(),
            upload_mode: mode,
            payload_format: PayloadFormat::ZipStoredV1,
            key_protection,
            payload_size: zip_plan.payload_size,
            chunk_count,
            uploaded_at_unix,
        };

        let metadata_aad = file_metadata_aad(&file_id);
        let record = UserFileRecord {
            file_id: file_id.clone(),
            state: FileState::Active,
            metadata_encrypted_by_user_vault: encrypt_json(
                &keys.user_vault_key,
                &metadata_aad,
                &metadata_plain,
            )?,
            user_fek,
            recovery_fek: None,
            pqc,
            chunks,
            created_at_unix: uploaded_at_unix,
            updated_at_unix: uploaded_at_unix,
        };

        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        user_vault.files.push(record);
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;
        emit_upload_progress(
            &progress,
            &operation_id,
            "auditing",
            metadata.len(),
            metadata.len(),
            98,
            "Writing encrypted metadata and audit record",
        );

        self.append_audit_with_key(
            &keys.audit_key,
            Role::User.audit_actor(),
            "file_uploaded",
            "SUCCESS",
            json!({
                "file_id": file_id,
                "original_size": metadata.len(),
                "payload_size": zip_plan.payload_size,
                "chunk_count": chunk_count,
                "payload_format": PayloadFormat::ZipStoredV1,
                "key_protection": key_protection,
                "mode": mode
            }),
        )
        .await?;

        emit_upload_progress(
            &progress,
            &operation_id,
            "complete",
            metadata.len(),
            metadata.len(),
            100,
            "Upload encrypted and committed",
        );

        Ok(FileListEntry {
            file_id,
            original_name,
            original_size: metadata.len(),
            original_blake3_b64: original_hash_b64,
            upload_mode: mode,
            payload_format: PayloadFormat::ZipStoredV1,
            key_protection,
            chunk_count,
            uploaded_at_unix,
        })
    }

    pub async fn download_file(
        &self,
        keys: &UnlockedUserKeys,
        file_id: String,
        destination_dir: Option<PathBuf>,
    ) -> VaultResult<DownloadResult> {
        let user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let record = user_vault
            .files
            .iter()
            .find(|record| record.file_id == file_id)
            .ok_or(VaultError::FileNotFound)?;
        if record.state != FileState::Active {
            return Err(VaultError::FileNotActive);
        }

        let metadata = decrypt_file_metadata(&keys.user_vault_key, record)?;
        let file_key = file_key_for_user(&keys.user_vault_key, record)?;

        let output_dir = destination_dir.unwrap_or_else(default_download_dir);
        fs::create_dir_all(&output_dir).await?;
        let output_path = unique_output_path(&output_dir, &metadata.original_name).await?;
        let mut output = fs::File::create(&output_path).await?;
        let mut hasher = blake3::Hasher::new();
        let mut bytes_written = 0u64;
        let mut zip_decoder = match metadata.payload_format {
            PayloadFormat::Raw => None,
            PayloadFormat::ZipStoredV1 => Some(ZipStoredDecoder::new(metadata.original_size)),
        };

        for chunk in &record.chunks {
            let chunk_path = self.paths.chunks_dir.join(&chunk.relative_path);
            let ciphertext = fs::read(&chunk_path).await?;
            let stored_plain = decrypt_chunk(
                &file_key,
                &record.file_id,
                chunk.index,
                &chunk.nonce_b64,
                &ciphertext,
            )?;
            let plaintext = if chunk.compressed {
                decompress_chunk(&stored_plain)?
            } else {
                stored_plain
            };
            if plaintext.len() as u64 != chunk.original_len {
                return Err(VaultError::Integrity(format!(
                    "chunk {} length mismatch",
                    chunk.index
                )));
            }
            if blake3_b64(&plaintext) != chunk.chunk_blake3_b64 {
                return Err(VaultError::Integrity(format!(
                    "chunk {} hash mismatch",
                    chunk.index
                )));
            }

            if let Some(decoder) = zip_decoder.as_mut() {
                for file_bytes in decoder.feed(&plaintext)? {
                    hasher.update(&file_bytes);
                    output.write_all(&file_bytes).await?;
                    bytes_written += file_bytes.len() as u64;
                }
            } else {
                hasher.update(&plaintext);
                output.write_all(&plaintext).await?;
                bytes_written += plaintext.len() as u64;
            }
        }

        if let Some(decoder) = zip_decoder.as_ref() {
            decoder.finish()?;
        }
        output.flush().await?;

        let calculated_hash = b64_encode(hasher.finalize().as_bytes());
        let verified = constant_time_eq(
            calculated_hash.as_bytes(),
            metadata.original_blake3_b64.as_bytes(),
        );
        if !verified {
            return Err(VaultError::Integrity(
                "downloaded plaintext hash did not match stored metadata".to_string(),
            ));
        }

        self.append_audit_with_key(
            &keys.audit_key,
            Role::User.audit_actor(),
            "file_downloaded",
            "SUCCESS",
            json!({ "file_id": record.file_id, "bytes_written": bytes_written }),
        )
        .await?;

        Ok(DownloadResult {
            file_id: record.file_id.clone(),
            output_path: output_path.to_string_lossy().to_string(),
            bytes_written,
            original_blake3_b64: calculated_hash,
            verified,
        })
    }

    pub async fn delete_request(
        &self,
        keys: &UnlockedUserKeys,
        file_id: String,
    ) -> VaultResult<DeleteRequestResult> {
        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let record = user_vault
            .files
            .iter_mut()
            .find(|record| record.file_id == file_id)
            .ok_or(VaultError::FileNotFound)?;
        if record.state != FileState::Active {
            return Err(VaultError::FileNotActive);
        }

        move_record_key_material_to_recovery(record, &keys.user_vault_key, &keys.recovery_key)?;
        record.state = FileState::PendingDelete;
        record.updated_at_unix = now_unix();
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        if !admin_vault
            .recovery_queue
            .iter()
            .any(|entry| entry.file_id == file_id)
        {
            admin_vault.recovery_queue.push(RecoveryRecord {
                file_id: file_id.clone(),
                requested_by: Role::User.audit_actor().to_string(),
                requested_at_unix: now_unix(),
                state: "PENDING_DELETE".to_string(),
            });
        }
        admin_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;

        self.append_audit_with_key(
            &keys.audit_key,
            Role::User.audit_actor(),
            "delete_requested",
            "SUCCESS",
            json!({ "file_id": file_id }),
        )
        .await?;

        Ok(DeleteRequestResult {
            file_id,
            state: FileState::PendingDelete,
            queued_for_admin_recovery: true,
        })
    }

    pub async fn audit_logs(&self, keys: &UnlockedAdminKeys) -> VaultResult<Vec<AuditView>> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        decrypt_audit_log(&admin_vault, &keys.audit_key)
    }

    pub async fn audit_tables(&self, keys: &UnlockedAdminKeys) -> VaultResult<AuditTables> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let audit_entries = decrypt_audit_log(&admin_vault, &keys.audit_key)?;
        Ok(build_audit_tables(
            &audit_entries,
            &admin_vault.auth_events,
            &admin_vault.tamper_alerts,
        ))
    }

    pub async fn export_audit_logs(
        &self,
        keys: &UnlockedAdminKeys,
        category: String,
    ) -> VaultResult<AuditExportResult> {
        let category = normalize_audit_export_category(&category)?;
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let audit_entries = decrypt_audit_log(&admin_vault, &keys.audit_key)?;
        let tables = build_audit_tables(
            &audit_entries,
            &admin_vault.auth_events,
            &admin_vault.tamper_alerts,
        );
        let output_dir = default_download_dir();
        fs::create_dir_all(&output_dir).await?;

        let (file_name, bytes, row_count) = match category.as_str() {
            "login_logs" => (
                "secure-vault-login-logs.csv",
                login_logs_csv(&tables.login_logs).into_bytes(),
                tables.login_logs.len(),
            ),
            "host_fingerprinting" => (
                "secure-vault-host-fingerprinting.csv",
                host_fingerprints_csv(&tables.host_fingerprints).into_bytes(),
                tables.host_fingerprints.len(),
            ),
            "operations_log" => (
                "secure-vault-operations-log.csv",
                operation_logs_csv(&tables.operation_logs).into_bytes(),
                tables.operation_logs.len(),
            ),
            "complete_raw" => {
                let raw = serde_json::json!({
                    "drive_id": admin_vault.drive_id,
                    "exported_at_unix": now_unix(),
                    "audit_log_sequence": admin_vault.audit_log.sequence,
                    "audit_log_last_hash_b64": admin_vault.audit_log.last_hash_b64,
                    "decrypted_audit_entries": audit_entries,
                    "auth_events": admin_vault.auth_events,
                    "tamper_alerts": admin_vault.tamper_alerts,
                    "recovery_queue": admin_vault.recovery_queue,
                });
                (
                    "secure-vault-complete-raw-audit-log.json",
                    serde_json::to_vec_pretty(&raw)?,
                    tables.raw_log_count,
                )
            }
            _ => {
                return Err(VaultError::InvalidInput(
                    "unsupported audit export category".to_string(),
                ));
            }
        };

        let output_path = unique_output_path(&output_dir, file_name).await?;
        let report_hash = blake3_b64(&bytes);
        fs::write(&output_path, bytes).await?;

        self.append_audit_with_key(
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "audit_log_exported",
            "SUCCESS",
            json!({
                "category": category,
                "row_count": row_count,
                "output_path_hash_blake3_b64": blake3_b64(output_path.to_string_lossy().as_bytes())
            }),
        )
        .await?;

        Ok(AuditExportResult {
            category,
            output_path: output_path.to_string_lossy().to_string(),
            report_blake3_b64: report_hash,
            row_count,
        })
    }

    pub async fn recovery_queue(&self) -> VaultResult<Vec<RecoveryView>> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        Ok(admin_vault
            .recovery_queue
            .into_iter()
            .map(|record| RecoveryView {
                file_id: record.file_id,
                requested_by: record.requested_by,
                requested_at_unix: record.requested_at_unix,
                state: record.state,
            })
            .collect())
    }

    pub async fn tamper_alerts(&self) -> VaultResult<Vec<TamperAlert>> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        Ok(admin_vault.tamper_alerts)
    }

    pub async fn recover_file(
        &self,
        keys: &UnlockedAdminKeys,
        file_id: String,
    ) -> VaultResult<RecoveryView> {
        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let record = user_vault
            .files
            .iter_mut()
            .find(|record| record.file_id == file_id)
            .ok_or(VaultError::FileNotFound)?;
        if record.state != FileState::PendingDelete {
            return Err(VaultError::InvalidInput(
                "only pending-delete files can be recovered".to_string(),
            ));
        }

        restore_record_key_material_from_recovery(
            record,
            &keys.recovery_key,
            &keys.user_vault_key,
        )?;
        record.state = FileState::Active;
        record.updated_at_unix = now_unix();
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let mut view = None;
        for entry in &mut admin_vault.recovery_queue {
            if entry.file_id == file_id {
                entry.state = "RECOVERED".to_string();
                view = Some(RecoveryView {
                    file_id: entry.file_id.clone(),
                    requested_by: entry.requested_by.clone(),
                    requested_at_unix: entry.requested_at_unix,
                    state: entry.state.clone(),
                });
            }
        }
        append_audit_record(
            &mut admin_vault,
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "file_recovered",
            "SUCCESS",
            json!({ "file_id": file_id }),
        )?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;

        view.ok_or(VaultError::FileNotFound)
    }

    pub async fn destroy_file(
        &self,
        keys: &UnlockedAdminKeys,
        file_id: String,
    ) -> VaultResult<RecoveryView> {
        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let record = user_vault
            .files
            .iter_mut()
            .find(|record| record.file_id == file_id)
            .ok_or(VaultError::FileNotFound)?;
        record.user_fek = None;
        record.recovery_fek = None;
        record.pqc = None;
        record.state = FileState::CryptoErased;
        record.updated_at_unix = now_unix();
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let mut view = None;
        for entry in &mut admin_vault.recovery_queue {
            if entry.file_id == file_id {
                entry.state = "CRYPTO_ERASED".to_string();
                view = Some(RecoveryView {
                    file_id: entry.file_id.clone(),
                    requested_by: entry.requested_by.clone(),
                    requested_at_unix: entry.requested_at_unix,
                    state: entry.state.clone(),
                });
            }
        }
        append_audit_record(
            &mut admin_vault,
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "file_destroyed",
            "SUCCESS",
            json!({ "file_id": file_id }),
        )?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;

        view.ok_or(VaultError::FileNotFound)
    }

    pub async fn reset_user_password(
        &self,
        keys: &UnlockedAdminKeys,
        new_user_passphrase: SecretString,
    ) -> VaultResult<()> {
        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let new_kdf = default_kdf_profile();
        let new_kek = derive_key(&new_user_passphrase, &new_kdf)?;
        user_vault.user_credential = CredentialEnvelope {
            kdf: new_kdf,
            wrapped_vault_key: wrap_key(
                &new_kek,
                &keys.user_vault_key,
                USER_VAULT_KEY_BY_USER_KEK,
            )?,
        };
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;

        self.append_audit_with_key(
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "user_password_reset",
            "SUCCESS",
            json!({}),
        )
        .await?;
        Ok(())
    }

    pub async fn clear_lockdown(&self, keys: &UnlockedAdminKeys) -> VaultResult<()> {
        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        admin_vault.lockdown = None;
        admin_vault.failed_admin_attempts = 0;
        append_audit_record(
            &mut admin_vault,
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "lockdown_cleared",
            "SUCCESS",
            json!({}),
        )?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await
    }

    pub async fn export_custody_report(
        &self,
        keys: &UnlockedAdminKeys,
        destination_dir: Option<PathBuf>,
    ) -> VaultResult<CustodyExportResult> {
        let admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let audit_entries = decrypt_audit_log(&admin_vault, &keys.audit_key)?;
        let report = CustodyReport {
            drive_id: admin_vault.drive_id.clone(),
            exported_at_unix: now_unix(),
            audit_entries,
            recovery_queue: admin_vault
                .recovery_queue
                .iter()
                .map(|record| RecoveryView {
                    file_id: record.file_id.clone(),
                    requested_by: record.requested_by.clone(),
                    requested_at_unix: record.requested_at_unix,
                    state: record.state.clone(),
                })
                .collect(),
            tamper_alerts: admin_vault.tamper_alerts.clone(),
        };

        let output_dir = destination_dir.unwrap_or_else(default_download_dir);
        fs::create_dir_all(&output_dir).await?;
        let output_path =
            unique_output_path(&output_dir, "secure-vault-custody-report.json").await?;
        let report_bytes = serde_json::to_vec_pretty(&report)?;
        let report_hash = blake3_b64(&report_bytes);
        fs::write(&output_path, report_bytes).await?;

        self.append_audit_with_key(
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "custody_report_exported",
            "SUCCESS",
            json!({ "output_path_hash_blake3_b64": blake3_b64(output_path.to_string_lossy().as_bytes()) }),
        )
        .await?;

        Ok(CustodyExportResult {
            output_path: output_path.to_string_lossy().to_string(),
            report_blake3_b64: report_hash,
        })
    }

    pub async fn crypto_erase_vault(
        &self,
        keys: &UnlockedAdminKeys,
        confirmation: String,
    ) -> VaultResult<CryptoEraseResult> {
        if confirmation != "CRYPTO ERASE VAULT" {
            return Err(VaultError::InvalidInput(
                "confirmation phrase must be exactly CRYPTO ERASE VAULT".to_string(),
            ));
        }

        let mut user_vault: UserVaultDisk = read_json(&self.paths.user_vault).await?;
        let destroyed_file_count = user_vault
            .files
            .iter()
            .filter(|record| record.state != FileState::CryptoErased)
            .count();
        for record in &mut user_vault.files {
            record.user_fek = None;
            record.recovery_fek = None;
            record.pqc = None;
            record.state = FileState::CryptoErased;
            record.updated_at_unix = now_unix();
        }
        user_vault.user_credential.wrapped_vault_key = destroyed_envelope();
        user_vault.audit_key_wrapped_by_user_vault = destroyed_envelope();
        user_vault.recovery_key_wrapped_by_user_vault = destroyed_envelope();
        user_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.user_vault, &user_vault).await?;

        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        append_audit_record(
            &mut admin_vault,
            &keys.audit_key,
            Role::Admin.audit_actor(),
            "vault_crypto_erased",
            "SUCCESS",
            json!({ "destroyed_file_count": destroyed_file_count }),
        )?;
        admin_vault.admin_credential.wrapped_vault_key = destroyed_envelope();
        admin_vault.audit_key_wrapped_by_admin_vault = destroyed_envelope();
        admin_vault.recovery_key_wrapped_by_admin_vault = destroyed_envelope();
        admin_vault.user_vault_key_wrapped_by_recovery_key = destroyed_envelope();
        admin_vault.lockdown = Some(LockdownRecord {
            reason: "vault cryptographic erase completed".to_string(),
            triggered_at_unix: now_unix(),
        });
        admin_vault.updated_at_unix = now_unix();
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;

        Ok(CryptoEraseResult {
            destroyed_file_count,
            lockdown: true,
        })
    }

    async fn append_audit_with_key(
        &self,
        audit_key: &KeyMaterial,
        actor: &str,
        action: &str,
        outcome: &str,
        details: serde_json::Value,
    ) -> VaultResult<AuditView> {
        let mut admin_vault: AdminVaultDisk = read_json(&self.paths.admin_vault).await?;
        let view =
            append_audit_record(&mut admin_vault, audit_key, actor, action, outcome, details)?;
        write_json_atomic(&self.paths.admin_vault, &admin_vault).await?;
        Ok(view)
    }
}

fn resolve_portable_root() -> VaultResult<PathBuf> {
    if let Some(root) = non_empty_env_path("SECURE_VAULT_ROOT")? {
        return Ok(root);
    }

    if let Some(appimage_path) = non_empty_env_path("APPIMAGE")? {
        if let Some(parent) = appimage_path.parent() {
            return absolutize_path(parent.to_path_buf());
        }
    }

    match std::env::current_exe() {
        Ok(exe_path) => {
            if let Some(root) = portable_root_from_executable(&exe_path) {
                absolutize_path(root)
            } else {
                std::env::current_dir().map_err(VaultError::from)
            }
        }
        Err(_) => std::env::current_dir().map_err(VaultError::from),
    }
}

fn non_empty_env_path(name: &str) -> VaultResult<Option<PathBuf>> {
    match std::env::var_os(name) {
        Some(value) if !value.as_os_str().is_empty() => {
            path_from_external_os_input(value).map(Some)
        }
        _ => Ok(None),
    }
}

fn portable_root_from_executable(exe_path: &Path) -> Option<PathBuf> {
    if let Some(bundle_root) = macos_app_bundle_root(exe_path) {
        return Some(bundle_root);
    }
    if let Some(workspace_root) = development_workspace_root_from_target_executable(exe_path) {
        return Some(workspace_root);
    }
    exe_path.parent().map(Path::to_path_buf)
}

fn development_workspace_root_from_target_executable(exe_path: &Path) -> Option<PathBuf> {
    let profile_dir = exe_path.parent()?;
    let profile_name = profile_dir.file_name()?.to_string_lossy();
    if !profile_name.eq_ignore_ascii_case("debug") && !profile_name.eq_ignore_ascii_case("release")
    {
        return None;
    }

    let target_dir = profile_dir.parent()?;
    if !target_dir
        .file_name()?
        .to_string_lossy()
        .eq_ignore_ascii_case("target")
    {
        return None;
    }

    let workspace_root = target_dir.parent()?;
    if workspace_root.join("Cargo.toml").is_file()
        && workspace_root
            .join("src-tauri")
            .join("Cargo.toml")
            .is_file()
    {
        Some(workspace_root.to_path_buf())
    } else {
        None
    }
}

fn macos_app_bundle_root(exe_path: &Path) -> Option<PathBuf> {
    for ancestor in exe_path.ancestors() {
        let is_app_bundle = ancestor
            .extension()
            .map(|extension| extension.to_string_lossy().eq_ignore_ascii_case("app"))
            .unwrap_or(false);
        if is_app_bundle {
            return ancestor.parent().map(Path::to_path_buf);
        }
    }
    None
}

fn path_from_external_os_input(input: OsString) -> VaultResult<PathBuf> {
    match input.into_string() {
        Ok(text) => path_from_external_input(&text),
        Err(value) => {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty() {
                Err(VaultError::InvalidInput(
                    "path must not be empty".to_string(),
                ))
            } else {
                absolutize_path(path)
            }
        }
    }
}

pub fn path_from_external_input(input: &str) -> VaultResult<PathBuf> {
    let path_text = strip_surrounding_quotes(input);
    if path_text.is_empty() {
        return Err(VaultError::InvalidInput(
            "path must not be empty".to_string(),
        ));
    }
    if path_text.chars().any(|ch| ch == '\0') {
        return Err(VaultError::InvalidInput(
            "path must not contain NUL bytes".to_string(),
        ));
    }
    let path = expand_home_path(path_text).unwrap_or_else(|| PathBuf::from(path_text));
    absolutize_path(path)
}

fn absolutize_path(path: PathBuf) -> VaultResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidInput(
            "path must not be empty".to_string(),
        ));
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn expand_home_path(path_text: &str) -> Option<PathBuf> {
    if path_text == "~" {
        return home_dir();
    }

    path_text
        .strip_prefix("~/")
        .or_else(|| path_text.strip_prefix("~\\"))
        .and_then(|rest| home_dir().map(|home| home.join(rest)))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn strip_surrounding_quotes(input: &str) -> &str {
    let mut value = input.trim();
    loop {
        let is_double_quoted = value.starts_with('"') && value.ends_with('"');
        let is_single_quoted = value.starts_with('\'') && value.ends_with('\'');
        if value.len() >= 2 && (is_double_quoted || is_single_quoted) {
            value = value[1..value.len() - 1].trim();
        } else {
            return value;
        }
    }
}

struct SourceProfile {
    blake3_b64: String,
    crc32: u32,
}

async fn inspect_source_file<F>(
    source_path: &Path,
    total_bytes: u64,
    operation_id: &str,
    progress: &F,
) -> VaultResult<SourceProfile>
where
    F: Fn(UploadProgress) + Send + Sync,
{
    let mut file = fs::File::open(source_path).await?;
    let mut buffer = vec![0u8; DEFAULT_CHUNK_SIZE];
    let mut hasher = blake3::Hasher::new();
    let mut crc32 = Crc32::new();
    let mut bytes_processed = 0u64;

    loop {
        let read_len = file.read(&mut buffer).await?;
        if read_len == 0 {
            break;
        }
        let chunk = &buffer[..read_len];
        hasher.update(chunk);
        crc32.update(chunk);
        bytes_processed = bytes_processed.saturating_add(read_len as u64);
        emit_upload_progress(
            progress,
            operation_id,
            "analyzing",
            bytes_processed,
            total_bytes,
            scaled_percent(1, 18, bytes_processed, total_bytes),
            "Scanning source file for integrity metadata",
        );
    }

    Ok(SourceProfile {
        blake3_b64: b64_encode(hasher.finalize().as_bytes()),
        crc32: crc32.finalize(),
    })
}

fn emit_upload_progress<F>(
    progress: &F,
    operation_id: &str,
    stage: &str,
    bytes_processed: u64,
    total_bytes: u64,
    percent: u8,
    message: &str,
) where
    F: Fn(UploadProgress) + Send + Sync,
{
    if operation_id.is_empty() {
        return;
    }

    progress(UploadProgress {
        operation_id: operation_id.to_string(),
        stage: stage.to_string(),
        bytes_processed,
        total_bytes,
        percent: percent.min(100),
        message: message.to_string(),
    });
}

fn scaled_percent(start: u8, end: u8, processed: u64, total: u64) -> u8 {
    if total == 0 {
        return end;
    }
    let span = end.saturating_sub(start) as f64;
    let ratio = (processed as f64 / total as f64).clamp(0.0, 1.0);
    start.saturating_add((span * ratio).round() as u8)
}

struct EncryptedChunkWriter<'a> {
    file_key: &'a KeyMaterial,
    file_id: &'a str,
    chunks_dir: &'a Path,
    staging_dir: PathBuf,
    chunk_suffix: &'a str,
    buffer: Vec<u8>,
    chunks: Vec<ChunkRecord>,
    index: u64,
}

impl<'a> EncryptedChunkWriter<'a> {
    fn new(
        file_key: &'a KeyMaterial,
        file_id: &'a str,
        chunks_dir: &'a Path,
        staging_dir: PathBuf,
        chunk_suffix: &'a str,
    ) -> Self {
        Self {
            file_key,
            file_id,
            chunks_dir,
            staging_dir,
            chunk_suffix,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE),
            chunks: Vec::new(),
            index: 0,
        }
    }

    async fn push(&mut self, mut bytes: &[u8]) -> VaultResult<()> {
        while !bytes.is_empty() {
            let available = DEFAULT_CHUNK_SIZE - self.buffer.len();
            let take_len = available.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take_len]);
            bytes = &bytes[take_len..];

            if self.buffer.len() == DEFAULT_CHUNK_SIZE {
                self.flush_buffer().await?;
            }
        }
        Ok(())
    }

    async fn finalize(mut self) -> VaultResult<Vec<ChunkRecord>> {
        if !self.buffer.is_empty() {
            self.flush_buffer().await?;
        }
        Ok(self.chunks)
    }

    async fn flush_buffer(&mut self) -> VaultResult<()> {
        let plaintext = std::mem::take(&mut self.buffer);
        let (nonce_b64, ciphertext) =
            encrypt_chunk(self.file_key, self.file_id, self.index, &plaintext)?;
        let chunk_file_name = format!("{:016}{}", self.index, self.chunk_suffix);
        let chunk_path = self.staging_dir.join(&chunk_file_name);
        fs::write(&chunk_path, &ciphertext).await?;

        self.chunks.push(ChunkRecord {
            index: self.index,
            relative_path: relative_chunk_path(self.chunks_dir, &chunk_path)?,
            nonce_b64,
            original_len: plaintext.len() as u64,
            stored_plain_len: plaintext.len() as u64,
            ciphertext_len: ciphertext.len() as u64,
            compressed: false,
            chunk_blake3_b64: blake3_b64(&plaintext),
        });
        self.index += 1;
        self.buffer = Vec::with_capacity(DEFAULT_CHUNK_SIZE);
        Ok(())
    }
}

fn chunk_suffix_for_mode(mode: UploadSecurityMode) -> &'static str {
    match mode {
        UploadSecurityMode::Fast => ".zip.aes256.chunk",
        UploadSecurityMode::SuperSecure => ".zip.mlkem1024.aes256.chunk",
    }
}

fn key_protection_for_mode(mode: UploadSecurityMode) -> FileKeyProtection {
    match mode {
        UploadSecurityMode::Fast => FileKeyProtection::Aes256GcmKeyWrap,
        UploadSecurityMode::SuperSecure => FileKeyProtection::MlKem1024Aes256GcmKeyWrap,
    }
}

fn wrap_file_key_for_upload(
    keys: &UnlockedUserKeys,
    file_key: &KeyMaterial,
    file_id: &str,
    mode: UploadSecurityMode,
) -> VaultResult<(Option<AeadEnvelope>, Option<PqcFileKeyEnvelope>)> {
    match mode {
        UploadSecurityMode::Fast => Ok((
            Some(wrap_key(
                &keys.user_vault_key,
                file_key,
                FILE_KEY_BY_USER_VAULT,
            )?),
            None,
        )),
        UploadSecurityMode::SuperSecure => {
            let (dk, ek) = MlKem1024::generate_keypair();
            let seed = dk.to_bytes();
            let (ciphertext, shared_key) = ek.encapsulate();
            let pqc_wrap_key = pqc_shared_secret_key(file_id, shared_key.as_slice());
            let pqc = PqcFileKeyEnvelope {
                algorithm: PQC_FILE_KEY_ALGORITHM.to_string(),
                kem_ciphertext_b64: b64_encode(ciphertext.as_slice()),
                fek_wrapped_by_pqc_shared_key: wrap_key(
                    &pqc_wrap_key,
                    file_key,
                    PQC_FILE_KEY_BY_SHARED_SECRET,
                )?,
                user_decapsulation_seed_wrapped_by_user_vault: Some(encrypt_bytes(
                    &keys.user_vault_key,
                    pqc_user_seed_aad(file_id).as_bytes(),
                    seed.as_slice(),
                )?),
                recovery_decapsulation_seed_wrapped_by_recovery_key: None,
            };
            Ok((None, Some(pqc)))
        }
    }
}

fn file_key_for_user(
    user_vault_key: &KeyMaterial,
    record: &UserFileRecord,
) -> VaultResult<KeyMaterial> {
    if let Some(pqc) = &record.pqc {
        let mut seed = decrypt_pqc_seed(
            user_vault_key,
            pqc.user_decapsulation_seed_wrapped_by_user_vault
                .as_ref()
                .ok_or_else(|| {
                    VaultError::Crypto(
                        "active PQC file missing user decapsulation seed".to_string(),
                    )
                })?,
            &pqc_user_seed_aad(&record.file_id),
        )?;
        let file_key = file_key_from_pqc_seed(&record.file_id, pqc, &seed);
        seed.zeroize();
        return file_key;
    }

    unwrap_key(
        user_vault_key,
        record.user_fek.as_ref().ok_or_else(|| {
            VaultError::Crypto("active file missing user FEK wrapper".to_string())
        })?,
        FILE_KEY_BY_USER_VAULT,
    )
}

fn move_record_key_material_to_recovery(
    record: &mut UserFileRecord,
    user_vault_key: &KeyMaterial,
    recovery_key: &KeyMaterial,
) -> VaultResult<()> {
    if let Some(pqc) = record.pqc.as_mut() {
        let mut seed = decrypt_pqc_seed(
            user_vault_key,
            pqc.user_decapsulation_seed_wrapped_by_user_vault
                .as_ref()
                .ok_or_else(|| {
                    VaultError::Crypto(
                        "active PQC file missing user decapsulation seed".to_string(),
                    )
                })?,
            &pqc_user_seed_aad(&record.file_id),
        )?;
        pqc.recovery_decapsulation_seed_wrapped_by_recovery_key = Some(encrypt_bytes(
            recovery_key,
            pqc_recovery_seed_aad(&record.file_id).as_bytes(),
            &seed,
        )?);
        pqc.user_decapsulation_seed_wrapped_by_user_vault = None;
        seed.zeroize();
        record.user_fek = None;
        record.recovery_fek = None;
        return Ok(());
    }

    let file_key = unwrap_key(
        user_vault_key,
        record.user_fek.as_ref().ok_or_else(|| {
            VaultError::Crypto("active file missing user FEK wrapper".to_string())
        })?,
        FILE_KEY_BY_USER_VAULT,
    )?;
    record.recovery_fek = Some(wrap_key(recovery_key, &file_key, FILE_KEY_BY_RECOVERY_KEY)?);
    record.user_fek = None;
    Ok(())
}

fn restore_record_key_material_from_recovery(
    record: &mut UserFileRecord,
    recovery_key: &KeyMaterial,
    user_vault_key: &KeyMaterial,
) -> VaultResult<()> {
    if let Some(pqc) = record.pqc.as_mut() {
        let mut seed = decrypt_pqc_seed(
            recovery_key,
            pqc.recovery_decapsulation_seed_wrapped_by_recovery_key
                .as_ref()
                .ok_or_else(|| {
                    VaultError::Crypto(
                        "pending PQC file missing recovery decapsulation seed".to_string(),
                    )
                })?,
            &pqc_recovery_seed_aad(&record.file_id),
        )?;
        pqc.user_decapsulation_seed_wrapped_by_user_vault = Some(encrypt_bytes(
            user_vault_key,
            pqc_user_seed_aad(&record.file_id).as_bytes(),
            &seed,
        )?);
        pqc.recovery_decapsulation_seed_wrapped_by_recovery_key = None;
        seed.zeroize();
        record.user_fek = None;
        record.recovery_fek = None;
        return Ok(());
    }

    let file_key = unwrap_key(
        recovery_key,
        record.recovery_fek.as_ref().ok_or_else(|| {
            VaultError::Crypto("pending file missing recovery FEK wrapper".to_string())
        })?,
        FILE_KEY_BY_RECOVERY_KEY,
    )?;
    record.user_fek = Some(wrap_key(user_vault_key, &file_key, FILE_KEY_BY_USER_VAULT)?);
    record.recovery_fek = None;
    Ok(())
}

fn decrypt_pqc_seed(
    key: &KeyMaterial,
    envelope: &AeadEnvelope,
    aad_label: &str,
) -> VaultResult<Vec<u8>> {
    let seed = decrypt_bytes(key, aad_label.as_bytes(), envelope)?;
    if seed.len() != 64 {
        return Err(VaultError::Crypto(
            "PQC decapsulation seed had invalid length".to_string(),
        ));
    }
    Ok(seed)
}

fn file_key_from_pqc_seed(
    file_id: &str,
    pqc: &PqcFileKeyEnvelope,
    seed_bytes: &[u8],
) -> VaultResult<KeyMaterial> {
    if pqc.algorithm != PQC_FILE_KEY_ALGORITHM {
        return Err(VaultError::Crypto(format!(
            "unsupported PQC file key algorithm {}",
            pqc.algorithm
        )));
    }

    let seed = Seed::try_from(seed_bytes)
        .map_err(|_| VaultError::Crypto("invalid ML-KEM-1024 seed length".to_string()))?;
    let dk = MlKem1024PrivateKey::from_seed(seed);
    let ciphertext_bytes = b64_decode(&pqc.kem_ciphertext_b64)?;
    let ciphertext = MlKem1024Ciphertext::try_from(ciphertext_bytes.as_slice())
        .map_err(|_| VaultError::Crypto("invalid ML-KEM-1024 ciphertext length".to_string()))?;
    let shared_key = dk.decapsulate(&ciphertext);
    let pqc_wrap_key = pqc_shared_secret_key(file_id, shared_key.as_slice());
    unwrap_key(
        &pqc_wrap_key,
        &pqc.fek_wrapped_by_pqc_shared_key,
        PQC_FILE_KEY_BY_SHARED_SECRET,
    )
}

fn pqc_shared_secret_key(file_id: &str, shared_secret: &[u8]) -> KeyMaterial {
    let mut material = Vec::with_capacity(file_id.len() + shared_secret.len() + 1);
    material.extend_from_slice(file_id.as_bytes());
    material.push(0);
    material.extend_from_slice(shared_secret);
    KeyMaterial::new(blake3::derive_key(
        "secure-vault:v1:ml-kem-1024:file-key-wrap",
        &material,
    ))
}

fn pqc_user_seed_aad(file_id: &str) -> String {
    format!("secure-vault:v1:pqc-decapsulation-seed:user:{file_id}")
}

fn pqc_recovery_seed_aad(file_id: &str) -> String {
    format!("secure-vault:v1:pqc-decapsulation-seed:recovery:{file_id}")
}

fn decrypt_file_metadata(
    user_vault_key: &KeyMaterial,
    record: &UserFileRecord,
) -> VaultResult<FileMetadata> {
    decrypt_json(
        user_vault_key,
        &file_metadata_aad(&record.file_id),
        &record.metadata_encrypted_by_user_vault,
    )
}

fn file_metadata_aad(file_id: &str) -> String {
    format!("secure-vault:v1:file-metadata:{file_id}")
}

fn load_or_create_drive_id(manifest_path: &Path) -> VaultResult<String> {
    if manifest_path.exists() {
        let bytes = std::fs::read(manifest_path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(drive_id) = value
            .get("payload")
            .and_then(|payload| payload.get("drive_id"))
            .and_then(|drive_id| drive_id.as_str())
        {
            return Ok(drive_id.to_string());
        }
    }
    Ok(Uuid::new_v4().to_string())
}

fn relative_chunk_path(chunks_dir: &Path, chunk_path: &Path) -> VaultResult<String> {
    let relative = chunk_path
        .strip_prefix(chunks_dir)
        .map_err(|error| VaultError::InvalidInput(error.to_string()))?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            ch if ch.is_control() => '_',
            ch => ch,
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string()
}

fn push_auth_event(admin_vault: &mut AdminVaultDisk, role: Role, status: &str, reason_code: &str) {
    let timestamp_unix = now_unix();
    let sequence = admin_vault
        .auth_events
        .last()
        .map(|event| event.sequence.saturating_add(1))
        .unwrap_or(1);
    admin_vault.auth_events.push(AuthEventRecord {
        sequence,
        role,
        timestamp_unix,
        status: status.to_string(),
        reason_code: reason_code.to_string(),
        host: current_host_fingerprint(),
    });
    admin_vault.updated_at_unix = timestamp_unix;
}

fn build_audit_tables(
    audit_entries: &[AuditView],
    auth_events: &[AuthEventRecord],
    tamper_alerts: &[TamperAlert],
) -> AuditTables {
    let mut login_rows = login_rows_from_events(auth_events, audit_entries);
    let mut host_rows = host_rows_from_events(auth_events, audit_entries);
    let mut operation_rows = operation_rows_from_events(audit_entries, auth_events, tamper_alerts);

    assign_login_serials(&mut login_rows);
    assign_host_serials(&mut host_rows);
    assign_operation_serials(&mut operation_rows);

    AuditTables {
        raw_log_count: audit_entries.len() + auth_events.len() + tamper_alerts.len(),
        login_logs: login_rows,
        host_fingerprints: host_rows,
        operation_logs: operation_rows,
    }
}

fn login_rows_from_events(
    auth_events: &[AuthEventRecord],
    audit_entries: &[AuditView],
) -> Vec<LoginLogRow> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    for event in auth_events {
        let username = role_label(event.role).to_string();
        let status = normalized_status(&event.status).to_string();
        seen.insert(login_seen_key(event.timestamp_unix, &username, &status));
        rows.push(LoginLogRow {
            serial_number: event.sequence,
            username,
            timestamp_unix: event.timestamp_unix,
            status,
        });
    }

    for entry in audit_entries {
        if !is_login_action(&entry.action) {
            continue;
        }

        let username = actor_label(&entry.actor);
        let status = status_from_outcome(&entry.outcome).to_string();
        if auth_events.iter().any(|event| {
            role_label(event.role) == username
                && normalized_status(&event.status) == status
                && event.timestamp_unix.abs_diff(entry.timestamp_unix) <= 5
        }) {
            continue;
        }
        if seen.insert(login_seen_key(entry.timestamp_unix, &username, &status)) {
            rows.push(LoginLogRow {
                serial_number: entry.sequence,
                username,
                timestamp_unix: entry.timestamp_unix,
                status,
            });
        }
    }

    rows
}

fn host_rows_from_events(
    auth_events: &[AuthEventRecord],
    audit_entries: &[AuditView],
) -> Vec<HostFingerprintLogRow> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    for event in auth_events {
        let row = host_row_from_fingerprint(event.sequence, event.timestamp_unix, &event.host);
        seen.insert(host_seen_key(&row));
        rows.push(row);
    }

    for entry in audit_entries {
        let Some(host) = host_from_audit_details(&entry.details) else {
            continue;
        };
        let row = host_row_from_fingerprint(entry.sequence, entry.timestamp_unix, &host);
        if seen.insert(host_seen_key(&row)) {
            rows.push(row);
        }
    }

    rows
}

fn operation_rows_from_events(
    audit_entries: &[AuditView],
    auth_events: &[AuthEventRecord],
    tamper_alerts: &[TamperAlert],
) -> Vec<OperationLogRow> {
    let mut rows = Vec::new();

    for event in auth_events {
        rows.push(OperationLogRow {
            serial_number: event.sequence,
            operation_done: auth_operation_label(event),
            timestamp_unix: event.timestamp_unix,
        });
    }

    for entry in audit_entries {
        if is_login_action(&entry.action) {
            continue;
        }

        rows.push(OperationLogRow {
            serial_number: entry.sequence,
            operation_done: audit_operation_label(entry),
            timestamp_unix: entry.timestamp_unix,
        });
    }

    for (index, alert) in tamper_alerts.iter().enumerate() {
        rows.push(OperationLogRow {
            serial_number: (index as u64).saturating_add(1),
            operation_done: tamper_operation_label(alert),
            timestamp_unix: alert.created_at_unix,
        });
    }

    rows
}

fn assign_login_serials(rows: &mut [LoginLogRow]) {
    rows.sort_by_key(|row| (row.timestamp_unix, row.serial_number));
    for (index, row) in rows.iter_mut().enumerate() {
        row.serial_number = (index as u64).saturating_add(1);
    }
}

fn assign_host_serials(rows: &mut [HostFingerprintLogRow]) {
    rows.sort_by_key(|row| (row.timestamp_unix, row.serial_number));
    for (index, row) in rows.iter_mut().enumerate() {
        row.serial_number = (index as u64).saturating_add(1);
    }
}

fn assign_operation_serials(rows: &mut [OperationLogRow]) {
    rows.sort_by_key(|row| (row.timestamp_unix, row.serial_number));
    for (index, row) in rows.iter_mut().enumerate() {
        row.serial_number = (index as u64).saturating_add(1);
    }
}

fn host_row_from_fingerprint(
    serial_number: u64,
    timestamp_unix: i64,
    host: &HostFingerprint,
) -> HostFingerprintLogRow {
    HostFingerprintLogRow {
        serial_number,
        hostname: fallback_unknown(&host.hostname),
        host_machine_info: fallback_unknown(&host.machine_family),
        os: normalize_os_label(&host.os),
        timestamp_unix,
    }
}

fn host_from_audit_details(details: &serde_json::Value) -> Option<HostFingerprint> {
    let host = details.get("host")?;
    let hostname = host
        .get("hostname")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let username_hash_blake3_b64 = host
        .get("username_hash_blake3_b64")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let architecture = host
        .get("architecture")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let os = host
        .get("os")
        .and_then(serde_json::Value::as_str)
        .map(normalize_os_label)
        .unwrap_or_else(|| "Unknown".to_string());
    let machine_family = host
        .get("machine_family")
        .and_then(serde_json::Value::as_str)
        .map(fallback_unknown)
        .unwrap_or_else(|| machine_family_from_arch(&os, &architecture));

    Some(HostFingerprint {
        hostname,
        username_hash_blake3_b64,
        architecture,
        machine_family,
        os,
    })
}

fn is_login_action(action: &str) -> bool {
    matches!(action, "admin_login" | "user_login")
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::User => "User",
        Role::Admin => "Admin",
    }
}

fn actor_label(actor: &str) -> String {
    match actor {
        "USER" => "User".to_string(),
        "ADMIN" => "Admin".to_string(),
        value => value.to_string(),
    }
}

fn normalized_status(status: &str) -> &'static str {
    if status.eq_ignore_ascii_case("successful") || status.eq_ignore_ascii_case("success") {
        "successful"
    } else {
        "failed"
    }
}

fn status_from_outcome(outcome: &str) -> &'static str {
    if outcome.eq_ignore_ascii_case("SUCCESS") {
        "successful"
    } else {
        "failed"
    }
}

fn auth_operation_label(event: &AuthEventRecord) -> String {
    let status = normalized_status(&event.status);
    match (event.role, status) {
        (Role::User, "successful") => "User login successful".to_string(),
        (Role::Admin, "successful") => "Admin login successful".to_string(),
        (Role::User, _) => "User login failed".to_string(),
        (Role::Admin, _) => "Admin login failed".to_string(),
    }
}

fn audit_operation_label(entry: &AuditView) -> String {
    match entry.action.as_str() {
        "vault_initialized" => "Vault initialized".to_string(),
        "file_uploaded" => "Upload file".to_string(),
        "file_downloaded" => "Download file".to_string(),
        "delete_requested" => "Deleted file requested".to_string(),
        "file_recovered" => "File recovered".to_string(),
        "file_destroyed" => "Deleted file".to_string(),
        "user_password_reset" => "Reset user password".to_string(),
        "lockdown_cleared" => "Lockdown cleared".to_string(),
        "custody_report_exported" => "Custody report exported".to_string(),
        "audit_log_exported" => "Audit log exported".to_string(),
        "vault_crypto_erased" => "Crypto erase vault".to_string(),
        action => format!(
            "{} ({})",
            action.replace('_', " "),
            status_from_outcome(&entry.outcome)
        ),
    }
}

fn tamper_operation_label(alert: &TamperAlert) -> String {
    if alert.alert_type == "failed_admin_threshold" {
        return format!("Lockdown triggered: {}", alert.message);
    }

    format!("Anomaly detected: {} - {}", alert.alert_type, alert.message)
}

fn login_seen_key(timestamp_unix: i64, username: &str, status: &str) -> String {
    format!("{timestamp_unix}:{username}:{status}")
}

fn host_seen_key(row: &HostFingerprintLogRow) -> String {
    format!(
        "{}:{}:{}:{}",
        row.timestamp_unix, row.hostname, row.host_machine_info, row.os
    )
}

fn normalize_os_label(os: &str) -> String {
    match os {
        "windows" | "Win" => "Win".to_string(),
        "macos" | "darwin" | "Mac" => "Mac".to_string(),
        "linux" | "Linux" => "Linux".to_string(),
        value if !value.trim().is_empty() => value.to_string(),
        _ => "Unknown".to_string(),
    }
}

fn machine_family_from_arch(os: &str, architecture: &str) -> String {
    match architecture {
        "x86_64" | "amd64" => "x64".to_string(),
        "x86" | "i386" | "i586" | "i686" => "x86".to_string(),
        "aarch64" | "arm64" if os == "Mac" => "Apple Silicon".to_string(),
        "aarch64" | "arm64" => "ARM64".to_string(),
        "arm" => "ARM".to_string(),
        value if !value.trim().is_empty() => value.to_string(),
        _ => "Unknown".to_string(),
    }
}

fn fallback_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "Unknown".to_string()
    } else {
        value.to_string()
    }
}

fn normalize_audit_export_category(category: &str) -> VaultResult<String> {
    let normalized = category.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "login" | "login_logs" => Ok("login_logs".to_string()),
        "host" | "hosts" | "host_fingerprint" | "host_fingerprinting" => {
            Ok("host_fingerprinting".to_string())
        }
        "operation" | "operations" | "operations_log" => Ok("operations_log".to_string()),
        "raw" | "complete" | "complete_raw" | "complete_logs" => Ok("complete_raw".to_string()),
        _ => Err(VaultError::InvalidInput(
            "audit category must be login_logs, host_fingerprinting, operations_log, or complete_raw"
                .to_string(),
        )),
    }
}

fn login_logs_csv(rows: &[LoginLogRow]) -> String {
    let mut csv = String::from("serial number,username,timestamp,status\n");
    for row in rows {
        push_csv_row(
            &mut csv,
            &[
                row.serial_number.to_string(),
                row.username.clone(),
                format_timestamp_utc(row.timestamp_unix),
                row.status.clone(),
            ],
        );
    }
    csv
}

fn host_fingerprints_csv(rows: &[HostFingerprintLogRow]) -> String {
    let mut csv = String::from("serial number,hostname,host machine info,os,timestamp\n");
    for row in rows {
        push_csv_row(
            &mut csv,
            &[
                row.serial_number.to_string(),
                row.hostname.clone(),
                row.host_machine_info.clone(),
                row.os.clone(),
                format_timestamp_utc(row.timestamp_unix),
            ],
        );
    }
    csv
}

fn operation_logs_csv(rows: &[OperationLogRow]) -> String {
    let mut csv = String::from("serial number,operation done,timestamp\n");
    for row in rows {
        push_csv_row(
            &mut csv,
            &[
                row.serial_number.to_string(),
                row.operation_done.clone(),
                format_timestamp_utc(row.timestamp_unix),
            ],
        );
    }
    csv
}

fn push_csv_row(csv: &mut String, columns: &[String]) {
    let line = columns
        .iter()
        .map(|value| csv_escape(value))
        .collect::<Vec<_>>()
        .join(",");
    csv.push_str(&line);
    csv.push('\n');
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn format_timestamp_utc(timestamp_unix: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(timestamp_unix) {
        Ok(value) => format!(
            "{:02}:{:02}:{:02} {:02}-{:02}-{:04}",
            value.hour(),
            value.minute(),
            value.second(),
            value.day(),
            u8::from(value.month()),
            value.year()
        ),
        Err(_) => "00:00:00 01-01-1970".to_string(),
    }
}

fn default_download_dir() -> PathBuf {
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(user_profile).join("Downloads");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join("Downloads");
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

async fn unique_output_path(dir: &Path, file_name: &str) -> VaultResult<PathBuf> {
    let clean_name = sanitize_file_name(file_name);
    let candidate = dir.join(&clean_name);
    if !fs::try_exists(&candidate).await? {
        return Ok(candidate);
    }

    let path = Path::new(&clean_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());

    for counter in 1..10_000u32 {
        let name = match extension {
            Some(extension) if !extension.is_empty() => {
                format!("{stem} ({counter}).{extension}")
            }
            _ => format!("{stem} ({counter})"),
        };
        let candidate = dir.join(name);
        if !fs::try_exists(&candidate).await? {
            return Ok(candidate);
        }
    }

    Err(VaultError::InvalidInput(
        "could not allocate a unique output file name".to_string(),
    ))
}

fn destroyed_envelope() -> AeadEnvelope {
    AeadEnvelope {
        nonce_b64: String::new(),
        ciphertext_b64: String::new(),
    }
}

async fn read_json<T: DeserializeOwned>(path: &Path) -> VaultResult<T> {
    let bytes = fs::read(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotInitialized
        } else {
            VaultError::Io(error.to_string())
        }
    })?;
    serde_json::from_slice(&bytes).map_err(VaultError::from)
}

async fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let temp_path = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&temp_path, bytes).await?;
    if fs::try_exists(path).await? {
        fs::remove_file(path).await?;
    }
    fs::rename(&temp_path, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileKeyProtection, PayloadFormat};
    use secrecy::SecretString;
    use tokio::fs;
    use uuid::Uuid;

    const USER_PASS: &str = "UserPassphrase@123";
    const ADMIN_PASS: &str = "AdminPassphrase@123";

    struct TempVault {
        root: PathBuf,
        store: VaultStore,
    }

    impl TempVault {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("secure-vault-{label}-{}", Uuid::new_v4()));
            let store = VaultStore::from_root(&root).expect("temp vault store");
            Self { root, store }
        }

        async fn initialize(&self) {
            self.store
                .initialize(
                    SecretString::new(USER_PASS.to_string()),
                    SecretString::new(ADMIN_PASS.to_string()),
                )
                .await
                .expect("initialize temp vault");
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn external_path_input_strips_quotes_and_absolutizes() {
        let cwd = std::env::current_dir().expect("current dir");
        let resolved = path_from_external_input(" \"portable-root\" ").expect("path");
        assert_eq!(resolved, cwd.join("portable-root"));
    }

    #[test]
    fn external_path_input_expands_home_prefix_when_available() {
        if let Some(home) = home_dir() {
            let resolved = path_from_external_input("~/vault-file.txt").expect("path");
            assert_eq!(resolved, home.join("vault-file.txt"));
        }
    }

    #[test]
    fn executable_root_detection_handles_macos_app_bundle() {
        let exe_path =
            PathBuf::from("/Volumes/SECURE_DRIVE/Start-macOS.app/Contents/MacOS/secure-vault");
        let resolved = portable_root_from_executable(&exe_path).expect("bundle root");
        assert_eq!(resolved, PathBuf::from("/Volumes/SECURE_DRIVE"));
    }

    #[test]
    fn executable_root_detection_handles_cargo_target_builds() {
        let workspace_root =
            std::env::temp_dir().join(format!("secure-vault-workspace-{}", Uuid::new_v4()));
        let src_tauri_dir = workspace_root.join("src-tauri");
        std::fs::create_dir_all(&src_tauri_dir).expect("create source manifest dir");
        std::fs::create_dir_all(workspace_root.join("target").join("debug"))
            .expect("create target dir");
        std::fs::write(workspace_root.join("Cargo.toml"), "[workspace]\n")
            .expect("write workspace manifest");
        std::fs::write(
            src_tauri_dir.join("Cargo.toml"),
            "[package]\nname = \"secure-vault\"\n",
        )
        .expect("write package manifest");

        let exe_path = workspace_root
            .join("target")
            .join("debug")
            .join("secure-vault.exe");
        let resolved = portable_root_from_executable(&exe_path).expect("workspace root");
        assert_eq!(resolved, workspace_root);

        let _ = std::fs::remove_dir_all(resolved);
    }

    #[tokio::test]
    async fn failed_admin_attempts_trigger_persistent_lockdown() {
        let temp = TempVault::new("admin-lockdown");
        temp.initialize().await;

        for attempt in 1..ADMIN_FAILED_LOGIN_LOCKDOWN_THRESHOLD {
            let auth = temp
                .store
                .authenticate_admin(SecretString::new("wrong-admin-passphrase".to_string()))
                .await;
            assert!(auth.is_err(), "attempt {attempt} should fail auth");
            let lockdown = temp
                .store
                .record_failed_admin_login()
                .await
                .expect("record failed admin login");
            assert!(
                lockdown.is_none(),
                "attempt {attempt} should not trigger lockdown before threshold"
            );
        }

        let auth = temp
            .store
            .authenticate_admin(SecretString::new("wrong-admin-passphrase".to_string()))
            .await;
        assert!(auth.is_err(), "threshold attempt should fail auth");
        let lockdown = temp
            .store
            .record_failed_admin_login()
            .await
            .expect("record threshold failed admin login")
            .expect("threshold should trigger lockdown");
        assert!(lockdown.contains("failed admin login attempts"));

        let persistent = temp
            .store
            .persistent_lockdown_reason()
            .await
            .expect("persistent lockdown read")
            .expect("persistent lockdown reason");
        assert_eq!(persistent, lockdown);

        let alerts = temp.store.tamper_alerts().await.expect("tamper alerts");
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == "failed_admin_threshold"),
            "failed admin threshold should create a tamper alert"
        );

        let admin_keys = temp
            .store
            .authenticate_admin(SecretString::new(ADMIN_PASS.to_string()))
            .await
            .expect("admin auth after lockdown");
        let tables = temp
            .store
            .audit_tables(&admin_keys)
            .await
            .expect("categorized audit tables");
        assert_eq!(
            tables
                .login_logs
                .iter()
                .filter(|row| row.username == "Admin" && row.status == "failed")
                .count(),
            ADMIN_FAILED_LOGIN_LOCKDOWN_THRESHOLD as usize,
            "failed admin attempts should be visible in Login Logs"
        );
        assert!(
            tables.host_fingerprints.len() >= ADMIN_FAILED_LOGIN_LOCKDOWN_THRESHOLD as usize,
            "failed login attempts should emit host fingerprint rows"
        );
        assert!(
            tables
                .operation_logs
                .iter()
                .any(|row| row.operation_done == "Admin login failed"),
            "failed logins should appear in Operations Log"
        );
        assert!(
            tables
                .operation_logs
                .iter()
                .any(|row| row.operation_done.starts_with("Lockdown triggered:")),
            "lockdown threshold should appear in Operations Log"
        );
    }

    #[tokio::test]
    async fn upload_download_delete_recover_and_destroy_for_all_modes() {
        for mode in [UploadSecurityMode::Fast, UploadSecurityMode::SuperSecure] {
            let temp = TempVault::new(match mode {
                UploadSecurityMode::Fast => "fast-flow",
                UploadSecurityMode::SuperSecure => "super-secure-flow",
            });
            temp.initialize().await;

            let source_path = temp.root.join(match mode {
                UploadSecurityMode::Fast => "sample-fast.txt",
                UploadSecurityMode::SuperSecure => "sample-super-secure.bin",
            });
            let source_bytes = match mode {
                UploadSecurityMode::Fast => b"fast mode payload\nwith multiple lines\n".to_vec(),
                UploadSecurityMode::SuperSecure => {
                    (0..4096).map(|value| (value % 251) as u8).collect()
                }
            };
            fs::write(&source_path, &source_bytes)
                .await
                .expect("write source");

            let user_keys = temp
                .store
                .authenticate_user(SecretString::new(USER_PASS.to_string()))
                .await
                .expect("user auth");
            let uploaded = temp
                .store
                .upload_file(&user_keys, source_path.clone(), mode)
                .await
                .expect("upload file");
            assert_eq!(uploaded.payload_format, PayloadFormat::ZipStoredV1);
            assert_eq!(
                uploaded.key_protection,
                match mode {
                    UploadSecurityMode::Fast => FileKeyProtection::Aes256GcmKeyWrap,
                    UploadSecurityMode::SuperSecure => FileKeyProtection::MlKem1024Aes256GcmKeyWrap,
                }
            );

            let chunk_dir = temp.store.paths().chunks_dir.join(&uploaded.file_id);
            let chunk_names = std::fs::read_dir(&chunk_dir)
                .expect("chunk dir")
                .map(|entry| {
                    entry
                        .expect("chunk entry")
                        .file_name()
                        .to_string_lossy()
                        .to_string()
                })
                .collect::<Vec<_>>();
            let expected_suffix = match mode {
                UploadSecurityMode::Fast => ".zip.aes256.chunk",
                UploadSecurityMode::SuperSecure => ".zip.mlkem1024.aes256.chunk",
            };
            assert!(
                chunk_names
                    .iter()
                    .all(|name| name.ends_with(expected_suffix)),
                "all new chunks should use the expected encrypted ZIP suffix"
            );

            let listed = temp.store.list_files(&user_keys).await.expect("list files");
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].file_id, uploaded.file_id);

            let download_dir = temp.root.join("downloads");
            let downloaded = temp
                .store
                .download_file(
                    &user_keys,
                    uploaded.file_id.clone(),
                    Some(download_dir.clone()),
                )
                .await
                .expect("download file");
            assert!(downloaded.verified);
            let roundtrip = fs::read(downloaded.output_path)
                .await
                .expect("read downloaded file");
            assert_eq!(roundtrip, source_bytes);

            let delete_result = temp
                .store
                .delete_request(&user_keys, uploaded.file_id.clone())
                .await
                .expect("delete request");
            assert_eq!(delete_result.state, FileState::PendingDelete);
            assert!(
                temp.store
                    .list_files(&user_keys)
                    .await
                    .expect("list after delete")
                    .is_empty(),
                "pending delete file should disappear from user list"
            );

            let admin_keys = temp
                .store
                .authenticate_admin(SecretString::new(ADMIN_PASS.to_string()))
                .await
                .expect("admin auth");
            let queue = temp.store.recovery_queue().await.expect("recovery queue");
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0].file_id, uploaded.file_id);
            assert_eq!(queue[0].state, "PENDING_DELETE");

            let recovered = temp
                .store
                .recover_file(&admin_keys, uploaded.file_id.clone())
                .await
                .expect("recover file");
            assert_eq!(recovered.state, "RECOVERED");
            assert_eq!(
                temp.store
                    .list_files(&user_keys)
                    .await
                    .expect("list after recovery")
                    .len(),
                1
            );

            temp.store
                .delete_request(&user_keys, uploaded.file_id.clone())
                .await
                .expect("second delete request");
            let destroyed = temp
                .store
                .destroy_file(&admin_keys, uploaded.file_id.clone())
                .await
                .expect("destroy file");
            assert_eq!(destroyed.state, "CRYPTO_ERASED");
            assert!(
                temp.store
                    .list_files(&user_keys)
                    .await
                    .expect("list after destroy")
                    .is_empty(),
                "destroyed file should not appear in active user list"
            );
        }
    }
}
