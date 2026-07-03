(function () {
  document.querySelectorAll("[data-copy-value]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.dataset.copyValue;
      if (!value) return;

      try {
        await navigator.clipboard.writeText(value);
        const label = btn.querySelector("[data-copy-label]");
        const original = label?.textContent;
        if (label) label.textContent = "Copied";
        btn.classList.add("ov-copy-btn--done");
        window.setTimeout(() => {
          if (label && original) label.textContent = original;
          btn.classList.remove("ov-copy-btn--done");
        }, 1600);
      } catch {
        /* clipboard unavailable */
      }
    });
  });
})();
