use crate::crypto::KeyMaterial;
use crate::crypto::{b64_decode, b64_encode, decrypt_json, encrypt_json, now_unix};
use crate::error::{VaultError, VaultResult};
use crate::models::{
    AdminVaultDisk, AuditLogDisk, AuditPlainRecord, AuditView, HostFingerprint, TamperAlert,
};
use serde_json::json;
use uuid::Uuid;

pub fn empty_audit_log() -> AuditLogDisk {
    AuditLogDisk {
        sequence: 0,
        last_hash_b64: b64_encode([0u8; 32]),
        entries: Vec::new(),
    }
}

pub fn append_audit_record(
    admin_vault: &mut AdminVaultDisk,
    audit_key: &KeyMaterial,
    actor: &str,
    action: &str,
    outcome: &str,
    details: serde_json::Value,
) -> VaultResult<AuditView> {
    let sequence = admin_vault.audit_log.sequence + 1;
    let timestamp_unix = now_unix();
    let previous_hash_b64 = admin_vault.audit_log.last_hash_b64.clone();
    let previous_hash = b64_decode(&previous_hash_b64)?;

    let plain = AuditPlainRecord {
        sequence,
        timestamp_unix,
        actor: actor.to_string(),
        action: action.to_string(),
        outcome: outcome.to_string(),
        details,
    };

    let canonical_record = serde_json::to_vec(&plain)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&previous_hash);
    hasher.update(&canonical_record);
    let record_hash_b64 = b64_encode(hasher.finalize().as_bytes());

    let aad = audit_aad(sequence);
    let encrypted_record = encrypt_json(audit_key, &aad, &plain)?;

    admin_vault.audit_log.sequence = sequence;
    admin_vault.audit_log.last_hash_b64 = record_hash_b64.clone();
    admin_vault
        .audit_log
        .entries
        .push(crate::models::AuditEnvelope {
            sequence,
            timestamp_unix,
            previous_hash_b64,
            record_hash_b64: record_hash_b64.clone(),
            encrypted_record,
        });
    admin_vault.updated_at_unix = now_unix();

    Ok(AuditView {
        sequence,
        timestamp_unix,
        actor: plain.actor,
        action: plain.action,
        outcome: plain.outcome,
        details: plain.details,
        record_hash_b64,
    })
}

pub fn decrypt_audit_log(
    admin_vault: &AdminVaultDisk,
    audit_key: &KeyMaterial,
) -> VaultResult<Vec<AuditView>> {
    let mut expected_previous_hash = b64_encode([0u8; 32]);
    let mut views = Vec::with_capacity(admin_vault.audit_log.entries.len());

    for entry in &admin_vault.audit_log.entries {
        if entry.previous_hash_b64 != expected_previous_hash {
            return Err(VaultError::Integrity(format!(
                "audit hash-chain break at sequence {}",
                entry.sequence
            )));
        }

        let aad = audit_aad(entry.sequence);
        let plain: AuditPlainRecord = decrypt_json(audit_key, &aad, &entry.encrypted_record)?;
        let previous_hash = b64_decode(&entry.previous_hash_b64)?;
        let canonical_record = serde_json::to_vec(&plain)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&previous_hash);
        hasher.update(&canonical_record);
        let calculated_hash_b64 = b64_encode(hasher.finalize().as_bytes());

        if calculated_hash_b64 != entry.record_hash_b64 {
            return Err(VaultError::Integrity(format!(
                "audit record hash mismatch at sequence {}",
                entry.sequence
            )));
        }

        expected_previous_hash = entry.record_hash_b64.clone();
        views.push(AuditView {
            sequence: plain.sequence,
            timestamp_unix: plain.timestamp_unix,
            actor: plain.actor,
            action: plain.action,
            outcome: plain.outcome,
            details: plain.details,
            record_hash_b64: entry.record_hash_b64.clone(),
        });
    }

    if expected_previous_hash != admin_vault.audit_log.last_hash_b64 {
        return Err(VaultError::Integrity(
            "audit terminal hash does not match the last entry".to_string(),
        ));
    }

    Ok(views)
}

pub fn add_tamper_alert(
    admin_vault: &mut AdminVaultDisk,
    alert_type: &str,
    severity: &str,
    message: &str,
) -> TamperAlert {
    let alert = TamperAlert {
        alert_id: Uuid::new_v4().to_string(),
        alert_type: alert_type.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        created_at_unix: now_unix(),
        cleared_at_unix: None,
    };
    admin_vault.tamper_alerts.push(alert.clone());
    admin_vault.updated_at_unix = now_unix();
    alert
}

pub fn host_observed_details() -> serde_json::Value {
    let host = current_host_fingerprint();
    json!({
        "hostname": host.hostname,
        "username_hash_blake3_b64": host.username_hash_blake3_b64,
        "os": host.os,
        "architecture": host.architecture,
        "machine_family": host.machine_family
    })
}

pub fn current_host_fingerprint() -> HostFingerprint {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());
    let os = display_os(std::env::consts::OS).to_string();
    let architecture = std::env::consts::ARCH.to_string();
    let machine_family =
        display_machine_family(std::env::consts::OS, std::env::consts::ARCH).to_string();

    HostFingerprint {
        hostname,
        username_hash_blake3_b64: crate::crypto::blake3_b64(username.as_bytes()),
        architecture,
        machine_family,
        os,
    }
}

fn audit_aad(sequence: u64) -> String {
    format!("secure-vault:v1:audit:{sequence}")
}

fn display_os(os: &str) -> &'static str {
    match os {
        "windows" => "Win",
        "macos" => "Mac",
        "linux" => "Linux",
        _ => "Unknown",
    }
}

fn display_machine_family(os: &str, architecture: &str) -> &'static str {
    match architecture {
        "x86_64" | "amd64" => "x64",
        "x86" | "i386" | "i586" | "i686" => "x86",
        "aarch64" | "arm64" if os == "macos" => "Apple Silicon",
        "aarch64" | "arm64" => "ARM64",
        "arm" => "ARM",
        _ => "Unknown",
    }
}
