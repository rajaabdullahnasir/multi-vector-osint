(function () {
  const ALLOWED_TYPES = new Set([
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/webp",
  ]);

  const EXTENSIONS = {
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    tif: "image/tiff",
    tiff: "image/tiff",
    webp: "image/webp",
  };

  const form = document.querySelector("[data-image-upload-form]");
  if (!form) return;

  const dropzone = form.querySelector("[data-dropzone]");
  const surface = form.querySelector("[data-dropzone-surface]");
  const input = form.querySelector("[data-dropzone-input]");
  const nativeWrap = form.querySelector("[data-dropzone-native]");
  const browseBtn = form.querySelector("[data-dropzone-browse]");
  const clearBtn = form.querySelector("[data-dropzone-clear]");
  const emptyState = form.querySelector("[data-dropzone-empty]");
  const previewState = form.querySelector("[data-dropzone-preview]");
  const previewImg = form.querySelector("[data-dropzone-preview-img]");
  const fileNameEl = form.querySelector("[data-dropzone-filename]");
  const fileMetaEl = form.querySelector("[data-dropzone-filemeta]");
  const errorEl = form.querySelector("[data-dropzone-error]");
  const submitBtn = form.querySelector("[data-dropzone-submit]");

  const maxBytes = Number(form.dataset.maxBytes || 10485760);

  let previewUrl = null;

  dropzone?.classList.add("ov-dropzone--enhanced");
  document.documentElement.classList.add("ov-js");

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function resolveMime(file) {
    if (file.type && ALLOWED_TYPES.has(file.type)) {
      return file.type;
    }
    const ext = file.name.split(".").pop()?.toLowerCase() || "";
    return EXTENSIONS[ext] || "";
  }

  function setError(message) {
    if (!errorEl) return;
    if (message) {
      errorEl.textContent = message;
      errorEl.hidden = false;
      dropzone?.classList.add("ov-dropzone--error");
    } else {
      errorEl.textContent = "";
      errorEl.hidden = true;
      dropzone?.classList.remove("ov-dropzone--error");
    }
  }

  function revokePreview() {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
  }

  function setDragActive(active) {
    dropzone?.classList.toggle("ov-dropzone--active", active);
  }

  function setSubmitEnabled(enabled) {
    if (!submitBtn) return;
    submitBtn.disabled = !enabled;
  }

  function validateFile(file) {
    if (!file) {
      return { ok: false, error: "Please select an image file." };
    }
    if (!resolveMime(file)) {
      return { ok: false, error: "Unsupported format. Use JPG, PNG, TIFF, or WebP." };
    }
    if (file.size > maxBytes) {
      const maxMb = Math.round(maxBytes / (1024 * 1024));
      return { ok: false, error: `File is too large. Maximum size is ${maxMb} MB.` };
    }
    if (file.size === 0) {
      return { ok: false, error: "Uploaded file is empty." };
    }
    return { ok: true };
  }

  function assignFile(file, options = {}) {
    const { silent = false } = options;
    const result = validateFile(file);
    if (!result.ok) {
      if (!silent) setError(result.error);
      setSubmitEnabled(false);
      return false;
    }

    if (input && input.files?.[0] !== file) {
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
    }

    setError("");
    revokePreview();
    previewUrl = URL.createObjectURL(file);

    if (previewImg) {
      previewImg.src = previewUrl;
      previewImg.alt = file.name;
    }
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileMetaEl) {
      fileMetaEl.textContent = `${formatBytes(file.size)} · ${resolveMime(file)}`;
    }

    dropzone?.classList.add("ov-dropzone--filled");
    setSubmitEnabled(true);
    return true;
  }

  function clearFile() {
    if (input) input.value = "";
    revokePreview();
    if (previewImg) {
      previewImg.removeAttribute("src");
      previewImg.removeAttribute("alt");
    }
    if (fileNameEl) fileNameEl.textContent = "";
    if (fileMetaEl) fileMetaEl.textContent = "";
    dropzone?.classList.remove("ov-dropzone--filled", "ov-dropzone--error", "ov-dropzone--active");
    setError("");
    setSubmitEnabled(false);
  }

  function openFilePicker() {
    if (dropzone?.classList.contains("ov-dropzone--filled")) return;
    input?.click();
  }

  browseBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openFilePicker();
  });

  surface?.addEventListener("click", (e) => {
    if (e.target.closest("[data-dropzone-clear], [data-dropzone-browse]")) return;
    if (dropzone?.classList.contains("ov-dropzone--filled")) return;
    openFilePicker();
  });

  clearBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearFile();
  });

  input?.addEventListener("change", () => {
    const file = input.files?.[0];
    if (file) assignFile(file);
    else clearFile();
  });

  form.addEventListener("dragover", (e) => {
    e.preventDefault();
  });

  form.addEventListener("drop", (e) => {
    if (!e.target.closest("[data-dropzone-surface]")) return;
    e.preventDefault();
  });

  ["dragenter", "dragover"].forEach((type) => {
    surface?.addEventListener(type, (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(true);
    });
  });

  ["dragleave", "drop"].forEach((type) => {
    surface?.addEventListener(type, (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);
    });
  });

  surface?.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) assignFile(file);
  });

  surface?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openFilePicker();
    }
  });

  form.addEventListener("submit", (e) => {
    const file = input?.files?.[0];
    if (!file || !validateFile(file).ok) {
      e.preventDefault();
      setError("Please select a valid image before submitting.");
      setSubmitEnabled(false);
      return;
    }
    if (!submitBtn) return;
    submitBtn.disabled = true;
    submitBtn.classList.add("ov-btn--loading");
    submitBtn.setAttribute("aria-busy", "true");
  });

  if (nativeWrap) nativeWrap.hidden = true;
  clearFile();
})();
