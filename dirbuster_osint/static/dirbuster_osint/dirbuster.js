/**
 * AJAX directory buster scan with loader overlay.
 */
(function () {
  const LOADER_STEPS = [
    "Calibrating soft-404 baseline…",
    "Brute-forcing common paths…",
    "Classifying responses…",
    "Filtering false positives…",
    "Building report…",
  ];

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showAlert(message, type) {
    const container = document.querySelector(".ov-content");
    if (!container) return;
    let banner = container.querySelector(".js-ajax-alert");
    if (!banner) {
      banner = document.createElement("div");
      banner.className = "ov-alert js-ajax-alert";
      banner.style.marginBottom = "var(--ov-space-4)";
      container.insertBefore(banner, container.firstChild);
    }
    banner.className = `ov-alert js-ajax-alert ov-alert--${type || "danger"}`;
    banner.textContent = message;
  }

  class ScanLoader {
    constructor(overlay) {
      this.overlay = overlay;
      this.statusEl = overlay?.querySelector(".js-loader-status");
      this.targetEl = overlay?.querySelector(".js-loader-target");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(target) {
      if (!this.overlay) return;
      if (this.targetEl) this.targetEl.textContent = target;
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = Math.min(this.stepIndex + 1, LOADER_STEPS.length - 1);
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 2500);
    }

    hide() {
      if (!this.overlay) return;
      this.overlay.classList.remove("is-active");
      this.overlay.setAttribute("aria-hidden", "true");
      document.body.style.overflow = "";
      if (this.stepTimer) {
        window.clearInterval(this.stepTimer);
        this.stepTimer = null;
      }
    }

    _setStatus(text) {
      if (this.statusEl) this.statusEl.textContent = text;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("[data-dirbuster-form]");
    if (!form) return;

    const targetInput = form.querySelector('input[name="target"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new ScanLoader(document.getElementById("dirbuster-loader"));
    const scanUrl = form.getAttribute("data-scan-url");

    if (!targetInput || !scanUrl) return;

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (!targetInput.value.trim()) {
        targetInput.focus();
        return;
      }

      const priorAlert = document.querySelector(".js-ajax-alert");
      if (priorAlert) priorAlert.remove();

      submitBtn.disabled = true;
      submitBtn.classList.add("ov-btn--loading");
      loader.show(targetInput.value.trim());

      const formData = new FormData(form);
      formData.set("csrfmiddlewaretoken", getCsrfToken(form));

      try {
        const response = await fetch(scanUrl, {
          method: "POST",
          headers: { "X-Requested-With": "XMLHttpRequest", Accept: "application/json" },
          body: formData,
          credentials: "same-origin",
        });

        let data = {};
        try {
          data = await response.json();
        } catch (parseErr) {
          throw new Error("Unexpected server response. Please try again.");
        }

        if (!response.ok || !data.ok) {
          let message = data.error;
          if (!message && data.errors) {
            const parts = [];
            for (const field in data.errors) {
              if (Array.isArray(data.errors[field])) parts.push(...data.errors[field]);
            }
            message = parts.join(" ");
          }
          showAlert(message || "Scan could not be completed.", "danger");
          return;
        }

        if (data.redirect_url) {
          loader._setStatus("Done — opening report…");
          window.location.href = data.redirect_url;
          return;
        }
        showAlert("Scan finished but no redirect was returned.", "warning");
      } catch (err) {
        showAlert(err.message || "Network error. Check your connection.", "danger");
      } finally {
        loader.hide();
        submitBtn.disabled = false;
        submitBtn.classList.remove("ov-btn--loading");
      }
    });
  });
})();
