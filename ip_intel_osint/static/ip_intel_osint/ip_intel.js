/**
 * AJAX IP/domain intelligence lookup with full-page loader overlay.
 */
(function () {
  const LOADER_STEPS = [
    "Resolving input…",
    "Checking geolocation…",
    "Looking up ISP / ASN…",
    "Querying RDAP registration…",
    "Building report…",
  ];

  function looksBlank(raw) {
    return !raw || !String(raw).trim();
  }

  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
  }

  function showFieldError(input, message) {
    let el = input.closest(".ov-field")?.querySelector(".js-query-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "ov-caption js-query-error";
      el.style.color = "var(--ov-color-danger)";
      input.closest(".ov-field")?.appendChild(el);
    }
    el.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  function clearFieldError(input) {
    const el = input.closest(".ov-field")?.querySelector(".js-query-error");
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
      this.queryEl = overlay?.querySelector(".js-loader-query");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(query) {
      if (!this.overlay) {
        return;
      }
      if (this.queryEl) {
        this.queryEl.textContent = query;
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
    const form = document.querySelector("[data-ip-intel-form]");
    if (!form) {
      return;
    }

    const input = form.querySelector('input[name="query"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new ScanLoader(document.getElementById("ip-intel-loader"));
    const scanUrl = form.getAttribute("data-scan-url");

    if (!input || !scanUrl) {
      return;
    }

    input.addEventListener("input", function () {
      if (!looksBlank(input.value)) {
        clearFieldError(input);
      }
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (looksBlank(input.value)) {
        showFieldError(input, "Enter an IP address or domain name.");
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
      loader.show(input.value.trim());

      const formData = new FormData();
      formData.append("query", input.value.trim());
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
          const queryErrors = data.errors?.query;
          const msg = Array.isArray(queryErrors)
            ? queryErrors.map((e) => e.message || e).join(" ")
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
