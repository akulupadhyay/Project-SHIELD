use crate::error::{CommandError, CommandResult};
use crate::models::{DeleteRequestResult, DownloadResult, FileListEntry, UploadSecurityMode};
use crate::state::AppState;
use crate::vault::path_from_external_input;
use tauri::{Emitter, State, Window};

const UPLOAD_PROGRESS_EVENT: &str = "vault-upload-progress";

#[tauri::command]
pub async fn list_files(state: State<'_, AppState>) -> CommandResult<Vec<FileListEntry>> {
    let keys = state
        .require_user_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .list_files(&keys)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn upload_file(
    window: Window,
    state: State<'_, AppState>,
    source_path: String,
    mode: UploadSecurityMode,
    operation_id: String,
) -> CommandResult<FileListEntry> {
    let keys = state
        .require_user_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    let source_path = path_from_external_input(&source_path).map_err(CommandError::from)?;
    let progress_window = window.clone();
    state
        .store
        .upload_file_with_progress(&keys, source_path, mode, operation_id, move |progress| {
            let _ = progress_window.emit(UPLOAD_PROGRESS_EVENT, progress);
        })
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn download_file(
    state: State<'_, AppState>,
    file_id: String,
    destination_dir: Option<String>,
) -> CommandResult<DownloadResult> {
    let keys = state
        .require_user_keys()
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
        .download_file(&keys, file_id, destination)
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn delete_request(
    state: State<'_, AppState>,
    file_id: String,
) -> CommandResult<DeleteRequestResult> {
    let keys = state
        .require_user_keys()
        .await
        .map_err(CommandError::from)?;
    let _guard = state.vault_lock.lock().await;
    state
        .store
        .delete_request(&keys, file_id)
        .await
        .map_err(CommandError::from)
}
