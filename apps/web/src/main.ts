import { uploadFile } from "./upload.js";
import {
  parseDownloadUrl,
  stripKeyFromHistory,
  fetchMeta,
  verifyPassword,
  downloadAndDecrypt,
} from "./download.js";

// ── DOM refs ─────────────────────────────────────────────────────────

const $ = <T extends HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

// Views
const uploadView = $<HTMLDivElement>("upload-view");
const downloadView = $<HTMLDivElement>("download-view");
const expiredView = $<HTMLDivElement>("expired-view");

// Upload elements
const dropzone = $<HTMLDivElement>("dropzone");
const fileInput = $<HTMLInputElement>("file-input");
const fileInfo = $<HTMLDivElement>("file-info");
const fileName = $<HTMLDivElement>("file-name");
const fileSize = $<HTMLDivElement>("file-size");
const expirySelect = $<HTMLSelectElement>("expiry");
const downloadsSelect = $<HTMLSelectElement>("downloads");
const passwordInput = $<HTMLInputElement>("password");
const summaryLine = $<HTMLDivElement>("summary-line");
const encryptBtn = $<HTMLButtonElement>("encrypt-btn");
const progressCard = $<HTMLDivElement>("progress-card");
const progressLabel = $<HTMLDivElement>("progress-label");
const progressFill = $<HTMLDivElement>("progress-fill");
const resultCard = $<HTMLDivElement>("result-card");
const shareLink = $<HTMLDivElement>("share-link");
const copyBtn = $<HTMLButtonElement>("copy-btn");

// Download elements
const dlLoading = $<HTMLDivElement>("dl-loading");
const dlHeader = $<HTMLDivElement>("dl-header");
const dlSize = $<HTMLDivElement>("dl-size");
const dlRemaining = $<HTMLDivElement>("dl-remaining");
const passwordPrompt = $<HTMLDivElement>("password-prompt");
const dlPasswordInput = $<HTMLInputElement>("dl-password");
const verifyBtn = $<HTMLButtonElement>("verify-btn");
const downloadAction = $<HTMLDivElement>("download-action");
const downloadBtn = $<HTMLButtonElement>("download-btn");
const dlProgress = $<HTMLDivElement>("dl-progress");
const dlProgressLabel = $<HTMLDivElement>("dl-progress-label");
const dlProgressFill = $<HTMLDivElement>("dl-progress-fill");
const dlComplete = $<HTMLDivElement>("dl-complete");
const dlError = $<HTMLDivElement>("dl-error");
const dlErrorText = $<HTMLDivElement>("dl-error-text");

// ── Route: detect mode from URL ──────────────────────────────────────

const parsed = parseDownloadUrl();

if (parsed) {
  // Download mode
  uploadView.classList.add("hidden");
  downloadView.classList.remove("hidden");
  stripKeyFromHistory();
  initDownload(parsed.blobId, parsed.key);
} else {
  // Upload mode
  initUpload();
}

// ── Upload mode ──────────────────────────────────────────────────────

function updateSummary() {
  const expiry = expirySelect.value === "1" ? "1h" : expirySelect.value === "24" ? "24h" : "7d";
  const dl = downloadsSelect.value === "1" ? "1 download" : `${downloadsSelect.value} downloads`;
  const pw = passwordInput.value ? "password set" : "no password";
  summaryLine.textContent = `AES-256-GCM \u00b7 ${expiry} expiry \u00b7 ${dl} \u00b7 ${pw}`;
}

function initUpload() {
  let selectedFile: File | null = null;

  // Update summary when options change
  expirySelect.addEventListener("change", updateSummary);
  downloadsSelect.addEventListener("change", updateSummary);
  passwordInput.addEventListener("input", updateSummary);

  // Drag and drop
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.dataTransfer!.dropEffect = "copy";
    dropzone.classList.add("active");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("active");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("active");
    const files = e.dataTransfer?.files;
    if (files?.length) selectFile(files[0]);
  });

  dropzone.addEventListener("click", () => fileInput.click());

  fileInput.addEventListener("change", () => {
    if (fileInput.files?.length) selectFile(fileInput.files[0]);
  });

  function selectFile(file: File) {
    if (file.size > 100 * 1024 * 1024) {
      alert("File exceeds 100MB limit.");
      return;
    }
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileInfo.classList.remove("hidden");
    encryptBtn.disabled = false;
  }

  // Encrypt & upload
  encryptBtn.addEventListener("click", async () => {
    if (!selectedFile) return;
    encryptBtn.disabled = true;
    progressCard.classList.remove("hidden");
    resultCard.classList.add("hidden");

    try {
      const result = await uploadFile({
        file: selectedFile,
        expiryHours: parseInt(expirySelect.value, 10),
        maxDownloads: parseInt(downloadsSelect.value, 10),
        password: passwordInput.value || undefined,
        onProgress: (label, pct) => {
          progressLabel.textContent = label;
          progressFill.style.width = `${pct}%`;
        },
      });

      progressCard.classList.add("hidden");
      resultCard.classList.remove("hidden");
      shareLink.textContent = result.url;
    } catch (err) {
      progressCard.classList.add("hidden");
      encryptBtn.disabled = false;
      alert(err instanceof Error ? err.message : "Upload failed");
    }
  });

  // Copy link
  copyBtn.addEventListener("click", async () => {
    const text = shareLink.textContent ?? "";
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = "Copied";
      setTimeout(() => { copyBtn.textContent = "Copy link"; }, 2000);
    } catch {
      // Fallback
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      copyBtn.textContent = "Copied";
      setTimeout(() => { copyBtn.textContent = "Copy link"; }, 2000);
    }
  });
}

// ── Download mode ────────────────────────────────────────────────────

async function initDownload(blobId: string, key: Uint8Array) {
  try {
    const meta = await fetchMeta(blobId);

    if (!meta) {
      downloadView.classList.add("hidden");
      expiredView.classList.remove("hidden");
      return;
    }

    // Hide loading, show file info
    dlLoading.classList.add("hidden");
    dlHeader.classList.remove("hidden");
    dlSize.textContent = formatBytes(meta.size_bytes);
    dlRemaining.textContent = `${meta.downloads_remaining} download${meta.downloads_remaining === 1 ? "" : "s"} left`;

    if (meta.has_password) {
      passwordPrompt.classList.remove("hidden");

      verifyBtn.addEventListener("click", async () => {
        const pw = dlPasswordInput.value;
        if (!pw) return;
        verifyBtn.disabled = true;

        try {
          const valid = await verifyPassword(blobId, pw);
          if (!valid) {
            dlPasswordInput.value = "";
            dlPasswordInput.placeholder = "Wrong password. Try again.";
            verifyBtn.disabled = false;
            return;
          }
          passwordPrompt.classList.add("hidden");
          await doDownload(blobId, key, meta);
        } catch (err) {
          verifyBtn.disabled = false;
          showDownloadError(err instanceof Error ? err.message : "Verification failed");
        }
      });
    } else {
      // No password — show download button
      downloadAction.classList.remove("hidden");

      downloadBtn.addEventListener("click", async () => {
        downloadAction.classList.add("hidden");
        await doDownload(blobId, key, meta);
      });
    }
  } catch (err) {
    showDownloadError(err instanceof Error ? err.message : "Failed to load file info");
  }
}

async function doDownload(
  blobId: string,
  key: Uint8Array,
  meta: { filename_enc: string; size_bytes: number; has_password: boolean; downloads_remaining: number; expires_at: number },
) {
  dlProgress.classList.remove("hidden");
  try {
    await downloadAndDecrypt(blobId, key, meta, (label, pct) => {
      dlProgressLabel.textContent = label;
      dlProgressFill.style.width = `${pct}%`;
    });
    dlProgress.classList.add("hidden");
    dlComplete.classList.remove("hidden");
  } catch (err) {
    dlProgress.classList.add("hidden");
    showDownloadError(err instanceof Error ? err.message : "Decryption failed");
  }
}

function showDownloadError(msg: string) {
  dlError.classList.remove("hidden");
  dlErrorText.textContent = msg;
}

// ── Utility ──────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return `${u === 0 ? v : v.toFixed(1)} ${units[u]}`;
}
