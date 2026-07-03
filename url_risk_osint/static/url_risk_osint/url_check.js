/**
 * AJAX URL risk check with loader overlay.
 */
(function () {
  const LOADER_STEPS = [
    "Validating URL…",
    "Running lexical analysis…",
    "Checking blacklist rules…",
    "Computing risk score…",
  ];

  function validateUrl(raw) {
    if (!raw || !String(raw).trim()) {
      return { ok: false, error: "URL is required." };
    }
    let value = raw.trim();
    if (value.length > 2048) {
      return { ok: false, error: "URL is too long (max 2048 characters)." };
    }
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value)) {
      value = `https://${value}`;
    }
    try {
      const parsed = new URL(value);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        return { ok: false, error: "Only http:// and https:// URLs are supported." };
      }
      if (!parsed.hostname) {
        return { ok: false, error: "URL must include a valid host." };
      }
      const host = parsed.hostname.toLowerCase();
      if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".localhost")) {
        return { ok: false, error: "Local or loopback URLs cannot be analyzed." };
      }
      if (parsed.username || parsed.password) {
        return { ok: false, error: "URLs with embedded credentials are not allowed." };
      }
      return { ok: true, value: parsed.href.replace(/#$/, "") };
    } catch (e) {
      return { ok: false, error: "Please enter a valid URL." };
    }
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-url-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-url-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-url-error");
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

  class CheckLoader {
    constructor(overlay) {
      this.overlay = overlay;
      this.statusEl = overlay?.querySelector(".js-loader-status");
      this.urlEl = overlay?.querySelector(".js-loader-url");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(url) {
      if (!this.overlay) {
        return;
      }
      if (this.urlEl) {
        this.urlEl.textContent = url.length > 80 ? `${url.slice(0, 77)}…` : url;
      }
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = (this.stepIndex + 1) % LOADER_STEPS.length;
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 1500);
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
    const form = document.querySelector("[data-url-risk-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="url"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new CheckLoader(document.getElementById("url-risk-loader"));
    const checkUrl = form.getAttribute("data-check-url");

    if (!input || !checkUrl) {
      return;
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (submitBtn.disabled) {
        return;
      }

      const validation = validateUrl(input.value);
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
      formData.append("url", validation.value);
      formData.append("csrfmiddlewaretoken", getCsrfToken(form));

      try {
        const response = await fetch(checkUrl, {
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
          const urlErrors = data.errors?.url;
          const msg = Array.isArray(urlErrors)
            ? urlErrors.join(" ")
            : data.error || "Analysis could not be completed.";
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
        showAlert("Analysis finished but no redirect was returned.", "warning");
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
