/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],

  theme: {
    extend: {
      colors: {
        bg: "rgb(var(--color-bg) / <alpha-value>)",
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        surfaceRaised: "rgb(var(--color-surface-raised) / <alpha-value>)",
        hairline: "rgb(var(--color-hairline) / <alpha-value>)",
        text: "rgb(var(--color-text) / <alpha-value>)",
        muted: "rgb(var(--color-muted) / <alpha-value>)",
        amber: "rgb(var(--color-amber) / <alpha-value>)",
        risk: "rgb(var(--color-risk) / <alpha-value>)",
        teal: "rgb(var(--color-teal) / <alpha-value>)",
        signal: "rgb(var(--color-signal) / <alpha-value>)",
      },

      fontFamily: {
        display: ["DM Sans", "sans-serif"],
        body: ["DM Sans", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },

      letterSpacing: {
        tightest: "-0.04em",
      },
    },
  },

  plugins: [],
};
