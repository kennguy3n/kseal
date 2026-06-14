/** @type {import('tailwindcss').Config} */

// Semantic color tokens are backed by CSS custom properties (see src/index.css)
// so a single `.dark` class on <html> flips the whole palette between the
// light and dark themes. Components reference the semantic names (canvas,
// surface, fg, line, accent…) rather than raw slate scales, which keeps both
// themes consistent and WCAG-AA legible from one source of truth.
function withVar(channel) {
  return `rgb(var(${channel}) / <alpha-value>)`;
}

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Page background and layered surfaces.
        canvas: withVar("--c-canvas"),
        surface: withVar("--c-surface"),
        elevated: withVar("--c-elevated"),
        field: withVar("--c-field"),
        // Hairline borders / dividers.
        line: {
          DEFAULT: withVar("--c-line"),
          strong: withVar("--c-line-strong"),
        },
        // Foreground text ramp.
        fg: {
          DEFAULT: withVar("--c-fg"),
          strong: withVar("--c-fg-strong"),
          muted: withVar("--c-fg-muted"),
          subtle: withVar("--c-fg-subtle"),
        },
        // Brand accent (links, primary actions, active nav).
        accent: {
          DEFAULT: withVar("--c-accent"),
          strong: withVar("--c-accent-strong"),
          contrast: withVar("--c-accent-contrast"),
        },
        // Retained for the existing brand identity / favicons.
        ink: "#0b1020",
        panel: "#11182b",
      },
      ringColor: {
        focus: withVar("--c-accent"),
      },
    },
  },
  plugins: [],
};
