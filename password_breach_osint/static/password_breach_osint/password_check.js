/**
 * AJAX password breach check (k-anonymity).
 */
(function () {
  const LOADER_STEPS = [
    "Hashing password locally (SHA-1)…",
    "Querying Pwned Passwords range API…",
    "Matching hash suffix…",
    "Building report…",
  ];

  function validatePassword(raw) {
    if (!raw || !String(raw)) {
      return { ok: false, error: "Password is required." };
    }
    if (raw.length > 128) {
      return { ok: false, error: "Password must be at most 128 characters." };
    }
    return { ok: true, value: raw };
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-password-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-password-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-password-error");
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
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show() {
      if (!this.overlay) {
        return;
      }
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = (this.stepIndex + 1) % LOADER_STEPS.length;
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 1800);
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
    const form = document.querySelector("[data-password-breach-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="password"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new CheckLoader(document.getElementById("password-breach-loader"));
    const checkUrl = form.getAttribute("data-check-url");

    if (!input || !checkUrl) {
      return;
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (submitBtn.disabled) {
        return;
      }

      const validation = validatePassword(input.value);
      if (!validation.ok) {
        showFieldError(input, validation.error);
        input.focus();
        return;
      }
      clearFieldError(input);

      const prior = document.querySelector(".js-ajax-alert");
      if (prior) {
        prior.remove();
      }

      submitBtn.disabled = true;
      submitBtn.classList.add("ov-btn--loading");
      loader.show();

      const formData = new FormData();
      formData.append("password", validation.value);
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
        } catch (e) {
          throw new Error("Unexpected server response.");
        }

        if (!response.ok || !data.ok) {
          const pwdErrors = data.errors?.password;
          const msg = Array.isArray(pwdErrors)
            ? pwdErrors.join(" ")
            : data.error || "Check could not be completed.";
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
        }
      } catch (err) {
        showAlert(err.message || "Network error.", "danger");
      } finally {
        loader.hide();
        submitBtn.disabled = false;
        submitBtn.classList.remove("ov-btn--loading");
        input.value = "";
      }
    });
  });
})();
