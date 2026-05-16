/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        sentinel: {
          navy: "#1c3b7a",
          navy2: "#0f1d3a",
          navyDark: "#0f1d3a",
          navyDeep: "#0b1220",
          gold: "#e0a82e",
          goldDark: "#b8860b",
          goldSoft: "#f4c85a",
          ink: "#0f172a",
          bg: "#f5f6f8",
          surface: "#ffffff",
          subtle: "#eef1f7",
          border: "#d7dde8",
          slate: "#1e293b",
          slate2: "#334155",
          danger: "#ef4444",
          warn: "#f59e0b",
          info: "#38bdf8",
          ok: "#10b981",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(15, 29, 58, 0.06), 0 8px 24px rgba(15, 29, 58, 0.08)",
        glow: "0 0 32px rgba(224, 168, 46, 0.3)",
        kev: "0 0 24px rgba(239, 68, 68, 0.55)",
      },
      keyframes: {
        radarPulse: {
          "0%": { transform: "scale(0.6)", opacity: "0.85" },
          "100%": { transform: "scale(2.6)", opacity: "0" },
        },
        kevPulse: {
          "0%": { transform: "scale(0.5)", opacity: "1" },
          "100%": { transform: "scale(3.4)", opacity: "0" },
        },
        glowPulse: {
          "0%, 100%": { opacity: "0.6" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        radar: "radarPulse 2s ease-out infinite",
        kev: "kevPulse 1.2s ease-out infinite",
        glow: "glowPulse 2.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
