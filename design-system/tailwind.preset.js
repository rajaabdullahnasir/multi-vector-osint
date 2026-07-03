/**
 * Tailwind CSS preset — OSINT Vector (TryHackMe-inspired)
 * @example tailwind.config.js
 *   module.exports = {
 *     presets: [require('./design-system/tailwind.preset')],
 *     content: ['./templates/**/*.html', './src/**/*.{js,tsx}'],
 *   };
 */
module.exports = {
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: "#9fef00",
          hover: "#b8ff33",
          muted: "rgba(159, 239, 0, 0.12)",
          navy: "#212c42",
        },
        canvas: "#0f1419",
        surface: {
          DEFAULT: "#212c42",
          elevated: "#1c2538",
          hover: "#2a3548",
        },
        ov: {
          text: { primary: "#f0f4f8", secondary: "#a8b3c4", muted: "#6b7a90" },
          success: "#3dd68c",
          warning: "#f5a623",
          danger: "#ff5b5b",
          info: "#5b9fff",
        },
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', "Segoe UI", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "Consolas", "monospace"],
      },
      borderRadius: {
        ov: { sm: "4px", md: "8px", lg: "12px", xl: "16px" },
      },
      boxShadow: {
        "ov-card":
          "0 2px 8px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.04)",
        "ov-glow": "0 0 20px rgba(159, 239, 0, 0.25)",
      },
      maxWidth: {
        ov: "1280px",
      },
      spacing: {
        sidebar: "260px",
        header: "64px",
      },
    },
  },
};
