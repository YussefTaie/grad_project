/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        surface: "#0B0F14",
        panel: "#111827",
        panelAlt: "#0f172a",
        accent: "#38bdf8",
        success: "#22c55e",
        warning: "#facc15",
        danger: "#ef4444",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(56, 189, 248, 0.12), 0 18px 40px rgba(2, 6, 23, 0.45)",
      },
      backgroundImage: {
        grid:
          "linear-gradient(rgba(148,163,184,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.08) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};
