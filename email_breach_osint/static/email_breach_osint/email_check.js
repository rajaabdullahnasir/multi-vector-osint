/**
 * AJAX email breach check with loader overlay.
 */
(function () {
  const EMAIL_RE =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

  const BLOCKED_DOMAINS = new Set(["example.com", "example.org", "test.com", "localhost", "invalid"]);

  const LOADER_STEPS = [
    "Validating email…",
    "Querying XposedOrNot check-email…",
    "Parsing breach list…",
    "Building report…",
  ];

  function validateEmail(raw) {
    if (!raw || !String(raw).trim()) {
      return { ok: false, error: "Email address is required." };
    }
    const value = raw.trim().toLowerCase();
    if (value.length > 254) {
      return { ok: false, error: "Email address is too long." };
    }
    if (!EMAIL_RE.test(value)) {
      return { ok: false, error: "Please enter a valid email address." };
    }
    const domain = value.split("@").pop();
    if (BLOCKED_DOMAINS.has(domain)) {
      return { ok: false, error: "This email domain cannot be checked." };
    }
    return { ok: true, value };
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-email-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-email-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-email-error");
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
      this.emailEl = overlay?.querySelector(".js-loader-email");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(email) {
      if (!this.overlay) {
        return;
      }
      if (this.emailEl) {
        this.emailEl.textContent = email;
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
    const form = document.querySelector("[data-email-breach-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="email"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new CheckLoader(document.getElementById("email-breach-loader"));
    const checkUrl = form.getAttribute("data-check-url");

    if (!input || !checkUrl) {
      return;
    }

    input.addEventListener("input", function () {
      const result = validateEmail(input.value);
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

      const validation = validateEmail(input.value);
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
      formData.append("email", validation.value);
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
          const emailErrors = data.errors?.email;
          const msg = Array.isArray(emailErrors)
            ? emailErrors.map((e) => e.message || e).join(" ")
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
          return;
        }
        showAlert("Check finished but no redirect was returned.", "warning");
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
