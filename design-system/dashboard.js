(function () {
  const el = document.getElementById("dashboard-chart-data");
  if (!el || typeof Chart === "undefined") return;

  const data = JSON.parse(el.textContent);
  const grid = "rgba(255, 255, 255, 0.06)";
  const tick = "#71717a";
  const accent = "#5b8def";
  const success = "#4ade80";
  const warning = "#fbbf24";
  const danger = "#f87171";

  const baseScale = {
    grid: { color: grid, drawBorder: false },
    ticks: { color: tick, font: { family: "Inter, system-ui, sans-serif", size: 11 } },
    border: { display: false },
  };

  Chart.defaults.color = tick;
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.padding = 14;
  Chart.defaults.plugins.legend.labels.color = tick;

  const activityCtx = document.getElementById("chart-activity");
  if (activityCtx) {
    new Chart(activityCtx, {
      type: "line",
      data: {
        labels: data.activity.labels,
        datasets: [
          {
            label: "Investigations",
            data: data.activity.values,
            borderColor: accent,
            backgroundColor: "rgba(91, 141, 239, 0.15)",
            fill: true,
            tension: 0.35,
            pointRadius: 2,
            pointHoverRadius: 4,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ...baseScale },
          y: { ...baseScale, beginAtZero: true, ticks: { ...baseScale.ticks, precision: 0 } },
        },
      },
    });
  }

  const modulesCtx = document.getElementById("chart-modules");
  if (modulesCtx) {
    new Chart(modulesCtx, {
      type: "bar",
      data: {
        labels: data.modules.labels,
        datasets: [
          {
            label: "Saved lookups",
            data: data.modules.values,
            backgroundColor: "rgba(91, 141, 239, 0.55)",
            borderColor: accent,
            borderWidth: 1,
            borderRadius: 4,
            maxBarThickness: 36,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ...baseScale },
          y: { ...baseScale, beginAtZero: true, ticks: { ...baseScale.ticks, precision: 0 } },
        },
      },
    });
  }

  const urlCtx = document.getElementById("chart-url-risk");
  if (urlCtx) {
    const total = data.urlRisk.values.reduce((a, b) => a + b, 0);
    new Chart(urlCtx, {
      type: "doughnut",
      data: {
        labels: data.urlRisk.labels,
        datasets: [
          {
            data: data.urlRisk.values,
            backgroundColor: [success, warning, danger],
            borderWidth: 0,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: { position: "bottom" },
          tooltip: {
            callbacks: {
              label(ctx) {
                const v = ctx.parsed;
                const pct = total ? Math.round((v / total) * 100) : 0;
                return ` ${ctx.label}: ${v} (${pct}%)`;
              },
            },
          },
        },
      },
    });
  }

  const exposureCtx = document.getElementById("chart-exposure");
  if (exposureCtx) {
    new Chart(exposureCtx, {
      type: "bar",
      data: {
        labels: data.exposure.labels,
        datasets: [
          {
            label: "Count",
            data: data.exposure.values,
            backgroundColor: [danger, danger, warning],
            borderRadius: 4,
            maxBarThickness: 48,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ...baseScale, beginAtZero: true, ticks: { ...baseScale.ticks, precision: 0 } },
          y: { ...baseScale },
        },
      },
    });
  }
})();
