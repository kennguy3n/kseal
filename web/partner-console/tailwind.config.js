/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Theme is toggled by adding/removing the `dark` class on <html>. Semantic
  // colors below are backed by CSS custom properties (see src/index.css) so the
  // same utility (e.g. `text-content`) resolves to the right value per theme.
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Legacy fixed tokens kept for compatibility; now theme-aware.
        ink: "rgb(var(--c-page) / <alpha-value>)",
        panel: "rgb(var(--c-panel) / <alpha-value>)",
        // Surfaces.
        page: "rgb(var(--c-page) / <alpha-value>)",
        raised: "rgb(var(--c-raised) / <alpha-value>)",
        hover: "rgb(var(--c-hover) / <alpha-value>)",
        field: "rgb(var(--c-field) / <alpha-value>)",
        // Text.
        heading: "rgb(var(--c-heading) / <alpha-value>)",
        content: "rgb(var(--c-content) / <alpha-value>)",
        muted: "rgb(var(--c-muted) / <alpha-value>)",
        subtle: "rgb(var(--c-subtle) / <alpha-value>)",
        // Borders.
        line: "rgb(var(--c-line) / <alpha-value>)",
        "line-strong": "rgb(var(--c-line-strong) / <alpha-value>)",
        // Accent.
        accent: "rgb(var(--c-accent) / <alpha-value>)",
        "accent-strong": "rgb(var(--c-accent-strong) / <alpha-value>)",
        "accent-fg": "rgb(var(--c-accent-fg) / <alpha-value>)",
      },
    },
  },
  plugins: [],
};
