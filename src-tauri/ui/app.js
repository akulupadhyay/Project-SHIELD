const state = {
  session: null,
  files: [],
  recoveryQueue: [],
  auditTables: null,
  busy: false,
  uploadOperationId: null,
  uploadProgressTimer: null,
  selectedUploadPath: "",
  activeUploadSource: "none",
  justInitialized: false,
  loginVisibleAfterInit: true,
  activeAdminSection: "placeholder",
  activeAuditCategory: "login_logs"
};

const els = {
  body: document.body,
  title: document.getElementById("view-title"),
  modePill: document.getElementById("mode-pill"),
  notice: document.getElementById("notice"),
  sessionSummary: document.getElementById("session-summary"),
  manifestSummary: document.getElementById("manifest-summary"),
  storageSummary: document.getElementById("storage-summary"),
  actionsSummary: document.getElementById("actions-summary"),
  setupPanel: document.getElementById("setup-panel"),
  postInitPanel: document.getElementById("post-init-panel"),
  loginPanel: document.getElementById("login-panel"),
  userPanel: document.getElementById("user-panel"),
  adminPanel: document.getElementById("admin-panel"),
  lockdownPanel: document.getElementById("lockdown-panel"),
  lockdownReason: document.getElementById("lockdown-reason"),
  filesBody: document.getElementById("files-body"),
  recoveryBody: document.getElementById("recovery-body"),
  adminOutput: document.getElementById("admin-output"),
  adminOutputTitle: document.getElementById("admin-output-title"),
  adminSections: Array.from(document.querySelectorAll("[data-admin-section]")),
  adminActionButtons: Array.from(document.querySelectorAll(".admin-actions button")),
  auditTableTitle: document.getElementById("audit-table-title"),
  auditTableHead: document.getElementById("audit-table-head"),
  auditTableBody: document.getElementById("audit-table-body"),
  auditExportCurrent: document.getElementById("audit-export-current"),
  auditModeButtons: Array.from(document.querySelectorAll(".audit-mode-actions button")),
  uploadProgressPanel: document.getElementById("upload-progress-panel"),
  uploadProgressStage: document.getElementById("upload-progress-stage"),
  uploadProgressPercent: document.getElementById("upload-progress-percent"),
  uploadProgressBar: document.getElementById("upload-progress-bar"),
  uploadProgressDetail: document.getElementById("upload-progress-detail"),
  uploadDropZone: document.getElementById("upload-drop-zone"),
  uploadFilePicker: document.getElementById("upload-file-picker"),
  uploadSelectedLabel: document.getElementById("upload-selected-label"),
  uploadSubmit: document.getElementById("upload-submit"),
  adminResetForm: document.getElementById("admin-reset-form"),
  adminRecoveryModal: document.getElementById("admin-recovery-modal"),
  adminRecoveryKeyValue: document.getElementById("admin-recovery-key-value")
};

function invoke(command, args) {
  const tauri = window.__TAURI__;
  if (!tauri || !tauri.core || typeof tauri.core.invoke !== "function") {
    return Promise.reject({
      code: "tauri_unavailable",
      message: "Tauri IPC is unavailable. Open this page inside the Secure Portable Vault app."
    });
  }
  return tauri.core.invoke(command, args || {});
}

async function listenForUploadProgress() {
  const tauri = window.__TAURI__;
  if (!tauri || !tauri.event || typeof tauri.event.listen !== "function") {
    return;
  }

  await tauri.event.listen("vault-upload-progress", (event) => {
    handleUploadProgress(event.payload || {});
  });
}

async function listenForFileDrops() {
  const tauri = window.__TAURI__;
  if (!tauri || !tauri.event || typeof tauri.event.listen !== "function") {
    return;
  }

  await tauri.event.listen("tauri://drag-enter", () => {
    els.uploadDropZone.classList.add("drag-active");
  });
  await tauri.event.listen("tauri://drag-leave", () => {
    els.uploadDropZone.classList.remove("drag-active");
  });
  await tauri.event.listen("tauri://drag-drop", (event) => {
    els.uploadDropZone.classList.remove("drag-active");
    const paths = event && event.payload && Array.isArray(event.payload.paths)
      ? event.payload.paths
      : [];
    if (paths.length !== 1) {
      showNotice("Drop exactly one file for each upload.", "error");
      return;
    }
    setSelectedUploadPath(paths[0], "Dropped file");
  });
}

function createOperationId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  return `upload-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function showNotice(message, type) {
  els.notice.textContent = message;
  els.notice.className = `notice ${type || ""}`.trim();
  els.notice.hidden = false;
}

function hideNotice() {
  els.notice.hidden = true;
  els.notice.textContent = "";
  els.notice.className = "notice";
}

function formatError(error) {
  if (!error) {
    return "Unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (error.message) {
    return `${error.code || "error"}: ${error.message}`;
  }
  return JSON.stringify(error, null, 2);
}

function clearSecrets(...ids) {
  ids.forEach((id) => {
    const input = document.getElementById(id);
    if (input) {
      input.value = "";
    }
  });
}

function sanitizedPathInput(value) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim();
}

function hasUnsafeControl(value) {
  return /[\u0000-\u001F\u007F]/.test(String(value || ""));
}

function isRepetitiveSecret(value) {
  const chars = Array.from(String(value || "").trim());
  if (chars.length < 2) {
    return true;
  }
  if (chars.every((char) => char === chars[0])) {
    return true;
  }
  const maxPattern = Math.min(6, Math.floor(chars.length / 2));
  for (let size = 1; size <= maxPattern; size += 1) {
    if (chars.length % size !== 0) {
      continue;
    }
    const pattern = chars.slice(0, size).join("");
    let repeated = true;
    for (let index = 0; index < chars.length; index += size) {
      if (chars.slice(index, index + size).join("") !== pattern) {
        repeated = false;
        break;
      }
    }
    if (repeated) {
      return true;
    }
  }
  return false;
}

function validatePassphraseClient(label, value) {
  const text = String(value || "");
  if (hasUnsafeControl(text)) {
    return `${label} must not contain control characters.`;
  }
  if (Array.from(text).length > 4096) {
    return `${label} is too long to process safely.`;
  }
  if (Array.from(text.trim()).length < 12) {
    return `${label} must be at least 12 characters.`;
  }
  if (isRepetitiveSecret(text)) {
    return `${label} must not be a repetitive pattern.`;
  }
  return null;
}

function setBusy(isBusy, message) {
  state.busy = isBusy;
  document.querySelectorAll("button, input, select").forEach((element) => {
    if (element.id !== "session-refresh") {
      element.disabled = isBusy;
    }
  });
  if (isBusy && message) {
    showNotice(message, "pending");
  }
  if (!isBusy) {
    syncUploadControls();
  }
}

async function withBusy(message, action) {
  setBusy(true, message);
  try {
    return await action();
  } finally {
    setBusy(false);
    if (state.session) {
      render(state.session);
    }
  }
}

async function refreshSession(options) {
  try {
    const session = await invoke("session_check");
    state.session = session;
    render(session);
    if (options && options.silent !== true) {
      showNotice("Session refreshed.", "success");
    }
    if (session.mode === "USER") {
      await loadFiles(true);
    }
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

function render(session) {
  const mode = session.mode || "LOCKED";
  els.body.className = `mode-${mode.toLowerCase().replaceAll("_", "-")}`;
  els.modePill.textContent = mode;
  els.title.textContent = titleForMode(mode);

  const role = session.role || "NONE";
  const expires = session.expires_at_unix
    ? new Date(session.expires_at_unix * 1000).toLocaleString()
    : "No active session";
  els.sessionSummary.textContent = `${role} | ${expires}`;

  const manifest = session.manifest_status || {};
  els.manifestSummary.textContent = `${manifest.status || "UNKNOWN"} | ${manifest.drive_id || "no drive id"}`;
  els.storageSummary.textContent = session.storage_root || "unresolved";
  els.actionsSummary.textContent = (session.allowed_actions || []).join(", ") || "none";

  const showPostInit = mode === "LOCKED" && state.justInitialized && !state.loginVisibleAfterInit;
  els.setupPanel.hidden = session.initialized === true;
  els.postInitPanel.hidden = !showPostInit;
  els.loginPanel.hidden = mode !== "LOCKED" || showPostInit;
  els.userPanel.hidden = mode !== "USER";
  els.adminPanel.hidden = mode !== "ADMIN";
  els.lockdownPanel.hidden = mode !== "LOCKDOWN";
  els.lockdownReason.textContent = session.lockdown_reason || "This drive is locked due to a security event.";

  if (mode === "ADMIN") {
    showAdminSection(state.activeAdminSection || "placeholder");
  } else {
    state.activeAdminSection = "placeholder";
    els.adminActionButtons.forEach((button) => button.classList.remove("active"));
  }

  if (mode !== "USER" && !state.uploadOperationId) {
    els.uploadProgressPanel.hidden = true;
  }

  if (!state.busy) {
    document.getElementById("logout-button").disabled = !session.authenticated;
    syncUploadControls();
  }
}

function titleForMode(mode) {
  switch (mode) {
    case "USER":
      return "User Mode";
    case "ADMIN":
      return "Admin Mode";
    case "LOCKDOWN":
      return "Lockdown Mode";
    case "UNINITIALIZED":
      return "Initialize Vault";
    default:
      return "Vault Locked";
  }
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function formatAuditTimestamp(unixSeconds) {
  const timestamp = Number(unixSeconds || 0);
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return "00:00:00 01-01-1970";
  }

  const value = new Date(timestamp * 1000);
  const pad = (number) => String(number).padStart(2, "0");
  return `${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())} ${pad(value.getDate())}-${pad(value.getMonth() + 1)}-${value.getFullYear()}`;
}

function showUploadProgress(payload) {
  const percent = Number.isFinite(Number(payload.percent))
    ? Math.max(0, Math.min(100, Number(payload.percent)))
    : 0;
  els.uploadProgressPanel.hidden = false;
  els.uploadProgressBar.value = percent;
  els.uploadProgressPercent.textContent = `${Math.round(percent)}%`;
  els.uploadProgressStage.textContent = payload.message || "Processing upload";
  const processed = formatBytes(payload.bytes_processed || 0);
  const total = formatBytes(payload.total_bytes || 0);
  els.uploadProgressDetail.textContent = `${payload.stage || "upload"} | ${processed} of ${total}`;
}

function handleUploadProgress(payload) {
  if (!payload || payload.operation_id !== state.uploadOperationId) {
    return;
  }
  showUploadProgress(payload);
}

function finishUploadProgress(message, success) {
  showUploadProgress({
    operation_id: state.uploadOperationId,
    stage: success ? "complete" : "failed",
    bytes_processed: 0,
    total_bytes: 0,
    percent: success ? 100 : Number(els.uploadProgressBar.value || 0),
    message
  });
  els.uploadProgressDetail.textContent = message;
  window.clearTimeout(state.uploadProgressTimer);
  state.uploadProgressTimer = window.setTimeout(() => {
    els.uploadProgressPanel.hidden = true;
    state.uploadOperationId = null;
  }, success ? 1600 : 4000);
}

function hideUploadProgress() {
  window.clearTimeout(state.uploadProgressTimer);
  els.uploadProgressPanel.hidden = true;
  state.uploadOperationId = null;
}

function currentUploadPath() {
  const pastedPath = sanitizedPathInput(document.getElementById("upload-source-path").value);
  if (state.activeUploadSource === "selected" && state.selectedUploadPath) {
    return state.selectedUploadPath;
  }
  return pastedPath;
}

function syncUploadControls() {
  if (!els.uploadSubmit) {
    return;
  }
  const mode = document.getElementById("upload-mode").value;
  const sourcePath = currentUploadPath();
  els.uploadSubmit.disabled = state.busy || !mode || !sourcePath;
}

function resetUploadSource() {
  state.selectedUploadPath = "";
  state.activeUploadSource = "none";
  document.getElementById("upload-source-path").value = "";
  els.uploadSelectedLabel.textContent = "Drag and drop a file here or choose from your OS explorer.";
  syncUploadControls();
}

function setSelectedUploadPath(path, sourceLabel) {
  const cleanPath = sanitizedPathInput(path);
  if (!cleanPath) {
    showNotice("Selected upload path was empty or unsafe.", "error");
    state.selectedUploadPath = "";
    state.activeUploadSource = "none";
    syncUploadControls();
    return;
  }
  state.selectedUploadPath = cleanPath;
  state.activeUploadSource = "selected";
  document.getElementById("upload-source-path").value = "";
  const fileName = cleanPath.split(/[\\/]/).filter(Boolean).pop() || cleanPath;
  els.uploadSelectedLabel.textContent = `${sourceLabel}: ${fileName}`;
  showNotice(`${sourceLabel} ready. Select encryption mode and upload.`, "success");
  syncUploadControls();
}

function handleFilePickerSelection() {
  const file = els.uploadFilePicker.files && els.uploadFilePicker.files[0];
  if (!file) {
    return;
  }
  const possiblePath = file.path || file.webkitRelativePath || "";
  if (possiblePath) {
    setSelectedUploadPath(possiblePath, "Selected file");
  } else {
    state.selectedUploadPath = "";
    state.activeUploadSource = "none";
    els.uploadSelectedLabel.textContent = `Selected file: ${file.name}`;
    showNotice(
      "The OS chooser did not expose a backend-readable path. Drag the file into the vault window or paste the path in the OR field.",
      "pending"
    );
    syncUploadControls();
  }
  els.uploadFilePicker.value = "";
}

function formatProtection(file) {
  const payload = file.payload_format === "ZIP_STORED_V1" ? "ZIP" : "RAW";
  const protection =
    file.key_protection === "ML_KEM_1024_AES256_GCM_KEY_WRAP"
      ? "ML-KEM-1024 + AES-256-GCM"
      : "AES-256-GCM";
  return `${file.upload_mode} / ${payload} / ${protection}`;
}

async function loadFiles(silent) {
  try {
    const files = await invoke("list_files");
    state.files = files;
    renderFiles(files);
    if (!silent) {
      showNotice(`Loaded ${files.length} file record(s).`, "success");
    }
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

async function loadRecoveryQueue(silent) {
  try {
    const queue = await invoke("admin_recovery_queue");
    state.recoveryQueue = queue;
    renderRecoveryQueue(queue);
    setAdminOutput(queue);
    if (!silent) {
      showNotice(`Loaded ${queue.length} recovery record(s).`, "success");
    }
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

function renderFiles(files) {
  els.filesBody.textContent = "";
  if (!files.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "muted";
    cell.textContent = "No active files in the user vault.";
    row.appendChild(cell);
    els.filesBody.appendChild(row);
    return;
  }

  files.forEach((file) => {
    const row = document.createElement("tr");
    row.appendChild(td(file.original_name));
    row.appendChild(td(formatBytes(file.original_size)));
    row.appendChild(td(String(file.chunk_count)));
    row.appendChild(td(formatProtection(file)));

    const actions = document.createElement("td");
    const wrapper = document.createElement("div");
    wrapper.className = "row-actions";

    const downloadButton = document.createElement("button");
    downloadButton.type = "button";
    downloadButton.textContent = "Download";
    downloadButton.addEventListener("click", () => downloadFile(file.file_id));

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.textContent = "Delete Request";
    deleteButton.addEventListener("click", () => requestDelete(file.file_id));

    wrapper.append(downloadButton, deleteButton);
    actions.appendChild(wrapper);
    row.appendChild(actions);
    els.filesBody.appendChild(row);
  });
}

function renderRecoveryQueue(queue) {
  els.recoveryBody.textContent = "";
  if (!queue.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "muted";
    cell.textContent = "No files are waiting for admin recovery or destruction.";
    row.appendChild(cell);
    els.recoveryBody.appendChild(row);
    return;
  }

  queue.forEach((record) => {
    const row = document.createElement("tr");
    row.appendChild(td(record.file_id));
    row.appendChild(td(record.state));
    row.appendChild(td(new Date(record.requested_at_unix * 1000).toLocaleString()));

    const actions = document.createElement("td");
    const wrapper = document.createElement("div");
    wrapper.className = "row-actions";

    const recoverButton = document.createElement("button");
    recoverButton.type = "button";
    recoverButton.textContent = "Recover";
    recoverButton.disabled = record.state !== "PENDING_DELETE";
    recoverButton.addEventListener("click", () => recoverFile(record.file_id));

    const destroyButton = document.createElement("button");
    destroyButton.type = "button";
    destroyButton.textContent = "Destroy";
    destroyButton.className = "danger-button";
    destroyButton.disabled = record.state === "CRYPTO_ERASED";
    destroyButton.addEventListener("click", () => destroyFile(record.file_id));

    wrapper.append(recoverButton, destroyButton);
    actions.appendChild(wrapper);
    row.appendChild(actions);
    els.recoveryBody.appendChild(row);
  });
}

async function loadAuditTables(category) {
  showAdminSection("audit", "load-audit");
  renderAuditLoading(category);
  try {
    const tables = await withBusy("Loading categorized audit logs...", () =>
      invoke("admin_audit_tables")
    );
    state.auditTables = tables;
    renderAuditCategory(category);
    showNotice(`Loaded ${tables.raw_log_count || 0} audit/security record(s).`, "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

function renderAuditLoading(category) {
  state.activeAuditCategory = category;
  setActiveAuditMode(category);
  const config = auditConfig(category);
  els.auditTableTitle.textContent = config.title;
  els.auditExportCurrent.hidden = config.exportCategory === "complete_raw";
  renderAuditTable(config.headers, [], "Loading audit records...");
}

function renderAuditCategory(category) {
  state.activeAuditCategory = category;
  setActiveAuditMode(category);
  const config = auditConfig(category);
  const tables = state.auditTables || {};
  const rows = config.rows(tables);
  els.auditTableTitle.textContent = config.title;
  els.auditExportCurrent.hidden = config.exportCategory === "complete_raw";
  renderAuditTable(config.headers, rows, config.empty);
}

function auditConfig(category) {
  switch (category) {
    case "host_fingerprinting":
      return {
        title: "Host Fingerprinting",
        exportCategory: "host_fingerprinting",
        headers: ["Serial Number", "Hostname", "Host Machine Info", "OS", "Timestamp"],
        empty: "No host fingerprint records are available.",
        rows: (tables) =>
          (tables.host_fingerprints || []).map((row) => [
            row.serial_number,
            row.hostname,
            row.host_machine_info,
            row.os,
            formatAuditTimestamp(row.timestamp_unix)
          ])
      };
    case "operations_log":
      return {
        title: "Operations Log",
        exportCategory: "operations_log",
        headers: ["Serial Number", "Operation Done", "Timestamp"],
        empty: "No operation records are available.",
        rows: (tables) =>
          (tables.operation_logs || []).map((row) => [
            row.serial_number,
            row.operation_done,
            formatAuditTimestamp(row.timestamp_unix)
          ])
      };
    case "complete_raw":
      return {
        title: "Complete Raw Logs",
        exportCategory: "complete_raw",
        headers: ["Action", "Result"],
        empty: "Use Download Complete Logs to export the raw encrypted-audit analysis bundle.",
        rows: () => []
      };
    case "login_logs":
    default:
      return {
        title: "Login Logs",
        exportCategory: "login_logs",
        headers: ["Serial Number", "Username", "Timestamp", "Status"],
        empty: "No login records are available.",
        rows: (tables) =>
          (tables.login_logs || []).map((row) => [
            row.serial_number,
            row.username,
            formatAuditTimestamp(row.timestamp_unix),
            row.status
          ])
      };
  }
}

function renderAuditTable(headers, rows, emptyMessage) {
  els.auditTableHead.textContent = "";
  els.auditTableBody.textContent = "";

  const headRow = document.createElement("tr");
  headers.forEach((header) => {
    const cell = document.createElement("th");
    cell.textContent = header;
    headRow.appendChild(cell);
  });
  els.auditTableHead.appendChild(headRow);

  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = headers.length;
    cell.className = "muted";
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    els.auditTableBody.appendChild(row);
    return;
  }

  rows.forEach((columns) => {
    const row = document.createElement("tr");
    columns.forEach((column) => row.appendChild(td(String(column))));
    els.auditTableBody.appendChild(row);
  });
}

function setActiveAuditMode(category) {
  const activeId = {
    login_logs: "audit-login-logs",
    host_fingerprinting: "audit-host-fingerprinting",
    operations_log: "audit-operations-log",
    complete_raw: "audit-complete-raw"
  }[category];
  els.auditModeButtons.forEach((button) => {
    button.classList.toggle("active", button.id === activeId);
  });
}

async function exportAuditLogs(category) {
  const config = auditConfig(category);
  try {
    const result = await withBusy(`Exporting ${config.title.toLowerCase()}...`, () =>
      invoke("admin_export_audit_logs", { category: config.exportCategory })
    );
    if (category === "complete_raw") {
      renderAuditTable(
        ["Action", "Result"],
        [["Download Complete Logs", `Raw log bundle exported to ${result.output_path}`]],
        "Raw log bundle exported."
      );
    }
    showNotice(
      `${config.title} exported to ${result.output_path}. Rows: ${result.row_count}.`,
      "success"
    );
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

function td(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}

async function downloadFile(fileId) {
  try {
    const result = await withBusy("Decrypting and exporting file...", () =>
      invoke("download_file", { fileId })
    );
    showNotice(`Downloaded to ${result.output_path}`, "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

async function requestDelete(fileId) {
  try {
    const result = await withBusy("Submitting delete request...", () =>
      invoke("delete_request", { fileId })
    );
    showNotice(`File ${result.file_id} moved to ${result.state}.`, "success");
    await loadFiles(true);
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

async function recoverFile(fileId) {
  try {
    const result = await withBusy("Recovering file for user access...", () =>
      invoke("admin_recover_file", { fileId })
    );
    showNotice(`Recovered ${result.file_id}.`, "success");
    await loadRecoveryQueue(true);
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

async function destroyFile(fileId) {
  const confirmed = window.confirm(
    "Destroy this file key material? Encrypted chunks may remain on disk, but this file becomes unrecoverable."
  );
  if (!confirmed) {
    return;
  }
  try {
    const result = await withBusy("Destroying file key material...", () =>
      invoke("admin_destroy_file", { fileId })
    );
    showNotice(`Destroyed ${result.file_id}.`, "success");
    await loadRecoveryQueue(true);
  } catch (error) {
    showNotice(formatError(error), "error");
  }
}

function setAdminOutput(value) {
  els.adminOutput.textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function showAdminSection(sectionName, activeButtonId) {
  state.activeAdminSection = sectionName;
  els.adminSections.forEach((section) => {
    section.hidden = section.dataset.adminSection !== sectionName;
  });
  if (activeButtonId) {
    els.adminActionButtons.forEach((button) => {
      button.classList.toggle("active", button.id === activeButtonId);
    });
  }
}

function showAdminOutput(title, value, activeButtonId) {
  showAdminSection("output", activeButtonId);
  els.adminOutputTitle.textContent = title;
  setAdminOutput(value);
}

function formatSecuritySummary(summary) {
  const groups = [
    ["Storage", [
      `Vault root: ${summary.vault_root}`,
      `Manifest: ${summary.manifest_path}`,
      `User vault: ${summary.user_vault_path}`,
      `Admin vault: ${summary.admin_vault_path}`,
      `Chunks: ${summary.chunks_dir}`
    ]],
    ["Encryption", summary.encryption_summary || []],
    ["Local Key Storage", summary.key_storage_summary || []],
    ["Runtime Unlocking", summary.runtime_key_summary || []],
    ["Manifest / Dev Mode", summary.manifest_summary || []]
  ];

  return groups
    .map(([title, lines]) => `${title}\n${lines.map((line) => `- ${line}`).join("\n")}`)
    .join("\n\n");
}

function showAdminRecoveryKey(presentation) {
  els.adminRecoveryKeyValue.textContent = presentation.recovery_key;
  els.adminRecoveryModal.hidden = false;
}

document.getElementById("initialize-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();
  const userPassphrase = document.getElementById("init-user-passphrase").value;
  const adminPassphrase = document.getElementById("init-admin-passphrase").value;
  const userValidation = validatePassphraseClient("User passphrase", userPassphrase);
  const adminValidation = validatePassphraseClient("Admin passphrase", adminPassphrase);
  if (userValidation || adminValidation) {
    showNotice(userValidation || adminValidation, "error");
    return;
  }
  if (userPassphrase === adminPassphrase) {
    showNotice("User and Admin passphrases must be different.", "error");
    return;
  }
  try {
    const session = await withBusy("Creating encrypted vault...", () =>
      invoke("initialize_vault", { userPassphrase, adminPassphrase })
    );
    clearSecrets("init-user-passphrase", "init-admin-passphrase");
    state.session = session;
    state.justInitialized = true;
    state.loginVisibleAfterInit = false;
    render(session);
    showNotice("Vault initialized. Continue to the login form.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  } finally {
    clearSecrets("init-user-passphrase", "init-admin-passphrase");
  }
});

document.getElementById("show-login-after-init").addEventListener("click", () => {
  state.loginVisibleAfterInit = true;
  if (state.session) {
    render(state.session);
  }
  showNotice("Login form is ready.", "success");
});

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();
  const role = document.getElementById("login-role").value;
  const passphrase = document.getElementById("login-passphrase").value;
  try {
    const session = await withBusy(`Verifying ${role.toLowerCase()} credentials...`, () =>
      invoke("login", { role, passphrase })
    );
    clearSecrets("login-passphrase");
    state.session = session;
    state.auditTables = null;
    state.justInitialized = false;
    state.loginVisibleAfterInit = true;
    render(session);
    showNotice(`Logged in as ${role}.`, "success");
    if (session.admin_recovery_key_one_time) {
      showAdminRecoveryKey(session.admin_recovery_key_one_time);
    }
    if (session.mode === "USER") {
      await loadFiles(true);
    }
  } catch (error) {
    showNotice(formatError(error), "error");
    await refreshSession({ silent: true });
  } finally {
    clearSecrets("login-passphrase");
  }
});

document.getElementById("show-admin-reset").addEventListener("click", () => {
  els.adminResetForm.hidden = false;
  showNotice("Enter the admin recovery key and new admin passphrase.", "pending");
});

document.getElementById("cancel-admin-reset").addEventListener("click", () => {
  els.adminResetForm.hidden = true;
  clearSecrets(
    "admin-reset-recovery-key",
    "admin-reset-new-passphrase",
    "admin-reset-confirm-passphrase"
  );
});

document.getElementById("admin-reset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();
  const recoveryKey = document.getElementById("admin-reset-recovery-key").value.trim();
  const newAdminPassphrase = document.getElementById("admin-reset-new-passphrase").value;
  const confirmPassphrase = document.getElementById("admin-reset-confirm-passphrase").value;
  const validation = validatePassphraseClient("New admin passphrase", newAdminPassphrase);
  if (validation) {
    showNotice(validation, "error");
    return;
  }
  if (newAdminPassphrase !== confirmPassphrase) {
    showNotice("New admin passphrase confirmation does not match.", "error");
    return;
  }
  try {
    const session = await withBusy("Verifying recovery key and resetting admin passphrase...", () =>
      invoke("reset_admin_password_with_recovery_key", { recoveryKey, newAdminPassphrase })
    );
    state.session = session;
    els.adminResetForm.hidden = true;
    clearSecrets(
      "admin-reset-recovery-key",
      "admin-reset-new-passphrase",
      "admin-reset-confirm-passphrase"
    );
    render(session);
    showNotice("Admin passphrase reset. Log in with the new admin passphrase.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  } finally {
    clearSecrets(
      "admin-reset-recovery-key",
      "admin-reset-new-passphrase",
      "admin-reset-confirm-passphrase"
    );
  }
});

document.getElementById("lockdown-recovery-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();
  const recoveryKey = document.getElementById("lockdown-recovery-key").value.trim();
  try {
    const session = await withBusy("Verifying recovery key and clearing lockdown...", () =>
      invoke("clear_lockdown_with_recovery_key", { recoveryKey })
    );
    clearSecrets("lockdown-recovery-key");
    state.session = session;
    state.justInitialized = false;
    state.loginVisibleAfterInit = true;
    render(session);
    showNotice("Lockdown cleared. Log in with the admin passphrase.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  } finally {
    clearSecrets("lockdown-recovery-key");
  }
});

document.getElementById("ack-admin-recovery-key").addEventListener("click", () => {
  els.adminRecoveryKeyValue.textContent = "";
  els.adminRecoveryModal.hidden = true;
});

document.getElementById("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();
  const sourcePath = currentUploadPath();
  const mode = document.getElementById("upload-mode").value;
  if (!sourcePath) {
    showNotice("Select a file, drop one into the upload box, or paste a file path.", "error");
    syncUploadControls();
    return;
  }
  if (!mode) {
    hideUploadProgress();
    showNotice("Select an encryption mode before uploading.", "error");
    syncUploadControls();
    return;
  }
  const operationId = createOperationId();
  state.uploadOperationId = operationId;
  window.clearTimeout(state.uploadProgressTimer);
  showUploadProgress({
    operation_id: operationId,
    stage: "queued",
    bytes_processed: 0,
    total_bytes: 0,
    percent: 0,
    message: "Waiting for backend upload pipeline"
  });
  try {
    const result = await withBusy("Packaging and encrypting file...", () =>
      invoke("upload_file", { sourcePath, mode, operationId })
    );
    resetUploadSource();
    finishUploadProgress("Upload encrypted and committed", true);
    showNotice(`Uploaded ${result.original_name}.`, "success");
    await loadFiles(true);
  } catch (error) {
    finishUploadProgress("Upload failed", false);
    showNotice(formatError(error), "error");
  }
});

document.getElementById("choose-upload-file").addEventListener("click", () => {
  hideNotice();
  els.uploadFilePicker.click();
});

els.uploadFilePicker.addEventListener("change", handleFilePickerSelection);

els.uploadDropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  els.uploadDropZone.classList.add("drag-active");
});

els.uploadDropZone.addEventListener("dragleave", () => {
  els.uploadDropZone.classList.remove("drag-active");
});

els.uploadDropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  els.uploadDropZone.classList.remove("drag-active");
  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  if (!file) {
    return;
  }
  const possiblePath = file.path || file.webkitRelativePath || "";
  if (possiblePath) {
    setSelectedUploadPath(possiblePath, "Dropped file");
  } else {
    showNotice(
      "The dropped file did not expose a backend-readable path. Use Tauri window drag/drop or paste the file path.",
      "pending"
    );
  }
});

document.getElementById("upload-source-path").addEventListener("input", (event) => {
  const cleanPath = sanitizedPathInput(event.target.value);
  if (event.target.value !== cleanPath) {
    event.target.value = cleanPath;
  }
  if (cleanPath) {
    state.activeUploadSource = "path";
    state.selectedUploadPath = "";
    const fileName = cleanPath.split(/[\\/]/).filter(Boolean).pop() || cleanPath;
    els.uploadSelectedLabel.textContent = `Using pasted path: ${fileName}`;
  } else {
    resetUploadSource();
    return;
  }
  syncUploadControls();
});

document.getElementById("upload-mode").addEventListener("change", () => {
  if (!document.getElementById("upload-mode").value) {
    hideUploadProgress();
  }
  syncUploadControls();
});

document.getElementById("refresh-files").addEventListener("click", () => loadFiles(false));

document.getElementById("session-refresh").addEventListener("click", () => refreshSession({ silent: false }));

document.getElementById("logout-button").addEventListener("click", async () => {
  try {
    const session = await withBusy("Logging out and dropping active keys...", () =>
      invoke("logout")
    );
    state.session = session;
    state.files = [];
    state.auditTables = null;
    state.recoveryQueue = [];
    state.justInitialized = false;
    state.loginVisibleAfterInit = true;
    renderFiles([]);
    render(session);
    showNotice("Logged out. Active keys were dropped by the backend.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

document.getElementById("load-audit").addEventListener("click", async () => {
  await loadAuditTables(state.activeAuditCategory || "login_logs");
});

document.getElementById("audit-login-logs").addEventListener("click", async () => {
  if (!state.auditTables) {
    await loadAuditTables("login_logs");
    return;
  }
  renderAuditCategory("login_logs");
});

document.getElementById("audit-host-fingerprinting").addEventListener("click", async () => {
  if (!state.auditTables) {
    await loadAuditTables("host_fingerprinting");
    return;
  }
  renderAuditCategory("host_fingerprinting");
});

document.getElementById("audit-operations-log").addEventListener("click", async () => {
  if (!state.auditTables) {
    await loadAuditTables("operations_log");
    return;
  }
  renderAuditCategory("operations_log");
});

document.getElementById("audit-complete-raw").addEventListener("click", async () => {
  state.activeAuditCategory = "complete_raw";
  showAdminSection("audit", "load-audit");
  setActiveAuditMode("complete_raw");
  els.auditTableTitle.textContent = "Complete Raw Logs";
  els.auditExportCurrent.hidden = true;
  renderAuditTable(
    ["Action", "Result"],
    [["Download Complete Logs", "Preparing raw audit bundle export..."]],
    "Preparing raw audit bundle export."
  );
  await exportAuditLogs("complete_raw");
});

els.auditExportCurrent.addEventListener("click", async () => {
  await exportAuditLogs(state.activeAuditCategory || "login_logs");
});

document.getElementById("load-recovery").addEventListener("click", async () => {
  showAdminSection("recovery", "load-recovery");
  withBusy("Loading recovery queue...", () => loadRecoveryQueue(false));
});

document.getElementById("load-alerts").addEventListener("click", async () => {
  showAdminOutput("Tamper Alerts", "Loading tamper alerts...", "load-alerts");
  try {
    const alerts = await withBusy("Loading tamper alerts...", () => invoke("admin_tamper_alerts"));
    showAdminOutput("Tamper Alerts", alerts, "load-alerts");
    showNotice(`Loaded ${alerts.length} tamper alert(s).`, "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

document.getElementById("show-clear-lockdown").addEventListener("click", () => {
  showAdminSection("clear-lockdown", "show-clear-lockdown");
});

document.getElementById("clear-lockdown").addEventListener("click", async () => {
  try {
    const session = await withBusy("Clearing lockdown state...", () =>
      invoke("admin_clear_lockdown")
    );
    state.session = session;
    render(session);
    showNotice("Lockdown cleared.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

document.getElementById("show-reset-password").addEventListener("click", () => {
  showAdminSection("reset-password", "show-reset-password");
});

document.getElementById("reset-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const newUserPassphrase = document.getElementById("new-user-passphrase").value;
  try {
    await withBusy("Resetting user passphrase...", () =>
      invoke("admin_reset_user_password", { newUserPassphrase })
    );
    clearSecrets("new-user-passphrase");
    showNotice("User password reset completed.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  } finally {
    clearSecrets("new-user-passphrase");
  }
});

document.getElementById("show-export-report").addEventListener("click", () => {
  showAdminSection("export-report", "show-export-report");
});

document.getElementById("export-report-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const raw = document.getElementById("report-destination").value.trim();
  const destinationDir = raw.length ? raw : null;
  try {
    const result = await withBusy("Exporting custody report...", () =>
      invoke("admin_export_custody_report", { destinationDir })
    );
    setAdminOutput(result);
    showNotice(`Report exported to ${result.output_path}.`, "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

document.getElementById("show-security-summary").addEventListener("click", async () => {
  showAdminOutput("Security & Keys", "Loading security summary...", "show-security-summary");
  try {
    const summary = await withBusy("Loading encryption and key storage summary...", () =>
      invoke("admin_security_summary")
    );
    showAdminOutput("Security & Keys", formatSecuritySummary(summary), "show-security-summary");
    showNotice("Security summary loaded.", "success");
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

document.getElementById("show-erase-vault").addEventListener("click", () => {
  showAdminSection("erase-vault", "show-erase-vault");
});

document.getElementById("erase-vault-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const confirmation = document.getElementById("erase-confirmation").value;
  try {
    const result = await withBusy("Performing cryptographic erase...", () =>
      invoke("admin_crypto_erase_vault", { confirmation })
    );
    document.getElementById("erase-confirmation").value = "";
    setAdminOutput(result);
    showNotice("Vault crypto-erase completed. Backend entered lockdown.", "success");
    await refreshSession({ silent: true });
  } catch (error) {
    showNotice(formatError(error), "error");
  }
});

listenForUploadProgress().catch((error) => {
  console.warn("Upload progress events unavailable", error);
});
listenForFileDrops().catch((error) => {
  console.warn("File drop events unavailable", error);
});
refreshSession({ silent: true });
