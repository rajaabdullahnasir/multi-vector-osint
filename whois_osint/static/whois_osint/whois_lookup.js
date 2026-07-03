/**
 * AJAX WHOIS lookup with full-page loader overlay.
 */
(function () {
  const DOMAIN_RE = /^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  const BLOCKED_EXACT = new Set(["localhost", "localhost.localdomain"]);
  const BLOCKED_TLDS = new Set(["local", "test", "invalid", "internal"]);

  const LOADER_STEPS = [
    "Validating domain…",
    "Connecting to WHOIS registry…",
    "Fetching registration data…",
    "Resolving DNS records…",
    "Building investigation report…",
  ];

  function validateDomain(raw) {
    if (!raw || !String(raw).trim()) {
      return { ok: false, error: "Domain name is required." };
    }
    let value = raw.trim().toLowerCase();
    if (value.startsWith("http://") || value.startsWith("https://")) {
      return { ok: false, error: "Enter a domain only (e.g. example.com), not a full URL." };
    }
    if (value.includes("/") || value.includes("?")) {
      return { ok: false, error: "Invalid domain format." };
    }
    value = value.replace(/\.$/, "");
    if (value.startsWith("www.")) {
      value = value.slice(4);
    }
    if (value.length > 253) {
      return { ok: false, error: "Domain name is too long." };
    }
    if (!DOMAIN_RE.test(value)) {
      return { ok: false, error: "Please enter a valid domain name (e.g. example.com)." };
    }
    if (BLOCKED_EXACT.has(value)) {
      return { ok: false, error: "This domain cannot be queried." };
    }
    if (BLOCKED_TLDS.has(value.split(".").pop())) {
      return { ok: false, error: "This domain cannot be queried." };
    }
    return { ok: true, value };
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-domain-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-domain-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-domain-error");
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

  class LookupLoader {
    constructor(overlay) {
      this.overlay = overlay;
      this.statusEl = overlay?.querySelector(".js-loader-status");
      this.domainEl = overlay?.querySelector(".js-loader-domain");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(domain) {
      if (!this.overlay) {
        return;
      }
      if (this.domainEl) {
        this.domainEl.textContent = domain;
      }
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = (this.stepIndex + 1) % LOADER_STEPS.length;
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 2200);
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
    const form = document.querySelector("[data-whois-lookup-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="domain"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new LookupLoader(document.getElementById("whois-loader"));
    const lookupUrl = form.getAttribute("data-lookup-url");

    if (!input || !lookupUrl) {
      return;
    }

    input.addEventListener("input", function () {
      const result = validateDomain(input.value);
      if (result.ok) {
        clearFieldError(input);
      } else {
        showFieldError(input, result.error);
      }
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      const validation = validateDomain(input.value);
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
      formData.append("domain", validation.value);
      formData.append("csrfmiddlewaretoken", getCsrfToken(form));

      try {
        const response = await fetch(lookupUrl, {
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
          const domainErrors = data.errors?.domain;
          const msg = Array.isArray(domainErrors)
            ? domainErrors.map((e) => e.message || e).join(" ")
            : data.error || "Lookup could not be completed.";
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
        showAlert("Lookup finished but no redirect was returned.", "warning");
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
