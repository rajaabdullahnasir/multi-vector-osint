/**
 * AJAX multi-vector investigation runner with a longer-running loader
 * overlay, since this chains up to 7 modules sequentially server-side.
 */
(function () {
  const LOADER_STEPS = [
    "Running WHOIS & DNS…",
    "Scanning for subdomains…",
    "Checking company footprint (SPF/DMARC/headers)…",
    "Assessing URL risk…",
    "Pivoting on discovered IP addresses…",
    "Checking discovered emails for breaches…",
    "Checking username across platforms…",
    "Assembling the entity map…",
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

  class InvestigationLoader {
    constructor(overlay) {
      this.overlay = overlay;
      this.statusEl = overlay?.querySelector(".js-loader-status");
      this.domainEl = overlay?.querySelector(".js-loader-domain");
      this.stepTimer = null;
      this.stepIndex = 0;
    }

    show(domain) {
      if (!this.overlay) return;
      if (this.domainEl) this.domainEl.textContent = domain;
      this.overlay.classList.add("is-active");
      this.overlay.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
      this.stepIndex = 0;
      this._setStatus(LOADER_STEPS[0]);
      // Slower cadence than single-module loaders — this genuinely takes longer.
      this.stepTimer = window.setInterval(() => {
        this.stepIndex = Math.min(this.stepIndex + 1, LOADER_STEPS.length - 1);
        this._setStatus(LOADER_STEPS[this.stepIndex]);
      }, 6000);
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
    const form = document.querySelector("[data-investigation-form]");
    if (!form) return;

    const domainInput = form.querySelector('input[name="domain"]');
    const submitBtn = form.querySelector("[type='submit']");
    const loader = new InvestigationLoader(document.getElementById("investigation-loader"));
    const runUrl = form.getAttribute("data-run-url");

    if (!domainInput || !runUrl) return;

    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      if (!domainInput.value.trim()) {
        domainInput.focus();
        return;
      }

      const priorAlert = document.querySelector(".js-ajax-alert");
      if (priorAlert) priorAlert.remove();

      submitBtn.disabled = true;
      submitBtn.classList.add("ov-btn--loading");
      loader.show(domainInput.value.trim());

      const formData = new FormData(form);
      formData.set("csrfmiddlewaretoken", getCsrfToken(form));

      try {
        // No client-side timeout override — this request is expected to
        // legitimately take up to ~2 minutes given how many modules run.
        const response = await fetch(runUrl, {
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
          showAlert(data.error || "Investigation could not be completed.", "danger");
          return;
        }

        if (data.redirect_url) {
          loader._setStatus("Done — opening report…");
          window.location.href = data.redirect_url;
          return;
        }
        showAlert("Investigation finished but no redirect was returned.", "warning");
      } catch (err) {
        showAlert(
          err.message || "Network error or request timed out. The server may still be finishing — check Recent investigations shortly.",
          "danger"
        );
      } finally {
        loader.hide();
        submitBtn.disabled = false;
        submitBtn.classList.remove("ov-btn--loading");
      }
    });
  });
})();
