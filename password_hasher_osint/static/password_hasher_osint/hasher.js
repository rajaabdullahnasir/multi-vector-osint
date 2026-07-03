/**
 * AJAX submit for password hasher forms (instant redirect to report).
 */
(function () {
  function getCsrfToken(form) {
    const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return input ? input.value : "";
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

  function wireForm(form) {
    const url = form.getAttribute("data-action-url");
    const submitBtn = form.querySelector("[type='submit']");
    if (!url || !submitBtn) {
      return;
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (submitBtn.disabled) {
        return;
      }

      const prior = document.querySelector(".js-ajax-alert");
      if (prior) {
        prior.remove();
      }

      submitBtn.disabled = true;
      submitBtn.classList.add("ov-btn--loading");

      const formData = new FormData(form);

      try {
        const response = await fetch(url, {
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
          const errors = data.errors;
          let msg = data.error || "Request failed.";
          if (errors) {
            msg = Object.values(errors).flat().join(" ");
          }
          showAlert(msg, "danger");
          return;
        }

        if (data.redirect_url) {
          window.location.href = data.redirect_url;
        }
      } catch (err) {
        showAlert(err.message || "Network error.", "danger");
      } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove("ov-btn--loading");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-hasher-hash-form], [data-hasher-compare-form]").forEach(wireForm);
  });
})();
