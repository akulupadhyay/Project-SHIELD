use crate::crypto::{b64_decode, blake3_b64, now_unix};
use crate::error::{VaultError, VaultResult};
use crate::models::ManifestRuntimeStatus;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use signature::Verifier;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDeviceManifest {
    #[serde(default = "default_manifest_mode")]
    pub manifest_mode: String,
    pub payload: DeviceManifestPayload,
    pub public_key_ed25519_b64: Option<String>,
    pub signature_ed25519_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceManifestPayload {
    pub schema_version: u32,
    pub drive_id: String,
    pub app_binary_blake3_b64: String,
    pub policy_version: u32,
    pub created_at_unix: i64,
}

pub fn verify_or_create_manifest(root: &Path) -> VaultResult<ManifestRuntimeStatus> {
    let manifest_path = root.join("signed-device-manifest.json");
    let app_hash = current_binary_hash()?;

    if !manifest_path.exists() {
        let manifest = SignedDeviceManifest {
            manifest_mode: "UNSIGNED_DEVELOPMENT".to_string(),
            payload: DeviceManifestPayload {
                schema_version: 1,
                drive_id: Uuid::new_v4().to_string(),
                app_binary_blake3_b64: app_hash,
                policy_version: 1,
                created_at_unix: now_unix(),
            },
            public_key_ed25519_b64: None,
            signature_ed25519_b64: None,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        std::fs::write(&manifest_path, bytes)?;
        return Ok(ManifestRuntimeStatus {
            status: "UNPROVISIONED".to_string(),
            drive_id: Some(manifest.payload.drive_id),
            message: "Created first-run unsigned development manifest. No Ed25519 production key is trusted until the manifest is provisioned and signed.".to_string(),
        });
    }

    let manifest_bytes = std::fs::read(&manifest_path)?;
    let mut manifest: SignedDeviceManifest = serde_json::from_slice(&manifest_bytes)?;

    match (
        &manifest.public_key_ed25519_b64,
        &manifest.signature_ed25519_b64,
    ) {
        (Some(public_key_b64), Some(signature_b64)) => {
            if manifest.payload.app_binary_blake3_b64 != app_hash {
                return Err(VaultError::Manifest(
                    "application binary hash does not match signed device manifest".to_string(),
                ));
            }
            verify_signature(&manifest.payload, public_key_b64, signature_b64)?;
            Ok(ManifestRuntimeStatus {
                status: "VERIFIED".to_string(),
                drive_id: Some(manifest.payload.drive_id),
                message: "Device manifest signature and application hash verified.".to_string(),
            })
        }
        _ => {
            let updated = manifest.payload.app_binary_blake3_b64 != app_hash;
            let mode_updated = manifest.manifest_mode != "UNSIGNED_DEVELOPMENT";
            if updated || mode_updated {
                manifest.payload.app_binary_blake3_b64 = app_hash;
                manifest.manifest_mode = "UNSIGNED_DEVELOPMENT".to_string();
                let bytes = serde_json::to_vec_pretty(&manifest)?;
                std::fs::write(&manifest_path, bytes)?;
            }

            Ok(ManifestRuntimeStatus {
                status: if updated {
                    "UNSIGNED_DEV_UPDATED".to_string()
                } else {
                    "UNSIGNED".to_string()
                },
                drive_id: Some(manifest.payload.drive_id),
                message: if updated {
                    "Unsigned development manifest was updated for the current rebuilt binary. No Ed25519 production key is trusted in this mode.".to_string()
                } else {
                    "Unsigned development manifest hash matches this binary. Provision public_key_ed25519_b64 and signature_ed25519_b64 for production locking."
                        .to_string()
                },
            })
        }
    }
}

pub fn manifest_path_for_root(root: &Path) -> PathBuf {
    root.join("signed-device-manifest.json")
}

fn default_manifest_mode() -> String {
    "LEGACY_UNSIGNED_OR_SIGNED".to_string()
}

fn verify_signature(
    payload: &DeviceManifestPayload,
    public_key_b64: &str,
    signature_b64: &str,
) -> VaultResult<()> {
    let public_key_bytes = b64_decode(public_key_b64)?;
    let signature_bytes = b64_decode(signature_b64)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| VaultError::Manifest("invalid Ed25519 public key length".to_string()))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| VaultError::Manifest("invalid Ed25519 signature length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|error| VaultError::Manifest(error.to_string()))?;
    let signature = Signature::from_bytes(&signature_array);
    let payload_bytes = serde_json::to_vec(payload)?;

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|error| VaultError::Manifest(error.to_string()))
}

fn current_binary_hash() -> VaultResult<String> {
    let exe_path = std::env::current_exe()?;
    let bytes = std::fs::read(exe_path)?;
    Ok(blake3_b64(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_unsigned_manifest_is_marked_as_unsigned_development() {
        let root = std::env::temp_dir().join(format!("secure-vault-manifest-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp manifest root");
        let manifest_path = root.join("signed-device-manifest.json");
        let legacy_manifest = serde_json::json!({
            "payload": {
                "schema_version": 1,
                "drive_id": Uuid::new_v4().to_string(),
                "app_binary_blake3_b64": "stale-dev-hash",
                "policy_version": 1,
                "created_at_unix": now_unix()
            },
            "public_key_ed25519_b64": null,
            "signature_ed25519_b64": null
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&legacy_manifest).expect("serialize legacy manifest"),
        )
        .expect("write legacy manifest");

        let status = verify_or_create_manifest(&root).expect("verify legacy manifest");
        assert_eq!(status.status, "UNSIGNED_DEV_UPDATED");

        let updated: SignedDeviceManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("read updated manifest"))
                .expect("parse updated manifest");
        assert_eq!(updated.manifest_mode, "UNSIGNED_DEVELOPMENT");

        let _ = std::fs::remove_dir_all(root);
    }
}
