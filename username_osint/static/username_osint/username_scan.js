/**
 * AJAX username scan with loader overlay.
 */
(function () {
  const USERNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]{1,30}[a-zA-Z0-9])?$/;
  const RESERVED = new Set([
    "admin",
    "administrator",
    "root",
    "system",
    "null",
    "undefined",
    "test",
    "guest",
    "support",
    "help",
    "api",
    "www",
  ]);

  const LOADER_STEPS = [
    "Validating username…",
    "Querying public profile URLs…",
    "Checking platforms in parallel…",
    "Building report…",
  ];

  function validateUsername(raw) {
    if (!raw || !String(raw).trim()) {
      return { ok: false, error: "Username is required." };
    }
    const value = raw.trim();
    if (value.length < 3) {
      return { ok: false, error: "Username must be at least 3 characters." };
    }
    if (value.length > 32) {
      return { ok: false, error: "Username must be at most 32 characters." };
    }
    if (!USERNAME_RE.test(value)) {
      return {
        ok: false,
        error:
          "Use letters, numbers, dots, hyphens, or underscores. Must start and end with a letter or number.",
      };
    }
    if (RESERVED.has(value.toLowerCase())) {
      return { ok: false, error: "This username cannot be searched." };
    }
    return { ok: true, value };
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-username-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-username-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-username-error");
    if (el) {
      el.remove();
    }
    input.removeAttribute("aria-invalid");
  }

  function showAlert(message, type) {
    const container = document.querySelector(".ov-content");
    if (!container) {
      return;
    }
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
      this.usernameEl = overlay?.querySelector(".js-loader-username");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(username) {
      if (!this.overlay) {
        return;
      }
      if (this.usernameEl) {
        this.usernameEl.textContent = username;
      }
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = (this.stepIndex + 1) % LOADER_STEPS.length;
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 2000);
    }

    hide() {
      if (!this.overlay) {
        return;
      }
      this.overlay.classList.remove("is-active");
      this.overlay.setAttribute("aria-hidden", "true");
      document.body.style.overflow = "";
      if (this.stepTimer) {
        window.clearInterval(this.stepTimer);
        this.stepTimer = null;
      }
    }

    _setStatus(text) {
      if (this.statusEl) {
        this.statusEl.textContent = text;
      }
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("[data-username-scan-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="username"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new ScanLoader(document.getElementById("username-scan-loader"));
    const scanUrl = form.getAttribute("data-scan-url");

    if (!input || !scanUrl) {
      return;
    }

    input.addEventListener("input", function () {
      const result = validateUsername(input.value);
      if (result.ok) {
        clearFieldError(input);
      } else {
        showFieldError(input, result.error);
      }
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (submitBtn.disabled) {
        return;
      }

      const validation = validateUsername(input.value);
      if (!validation.ok) {
        showFieldError(input, validation.error);
        input.focus();
        return;
      }
      clearFieldError(input);

      const priorAlert = document.querySelector(".js-ajax-alert");
      if (priorAlert) {
        priorAlert.remove();
      }

      submitBtn.disabled = true;
      submitBtn.classList.add("ov-btn--loading");
      loader.show(validation.value);

      const formData = new FormData();
      formData.append("username", validation.value);
      formData.append("csrfmiddlewaretoken", getCsrfToken(form));

      try {
        const response = await fetch(scanUrl, {
          method: "POST",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
            Accept: "application/json",
          },
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
          const usernameErrors = data.errors?.username;
          const msg = Array.isArray(usernameErrors)
            ? usernameErrors.join(" ")
            : data.error || "Scan could not be completed.";
          if (data.validation_failed) {
            showFieldError(input, msg);
          } else {
            showAlert(msg, "danger");
          }
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
