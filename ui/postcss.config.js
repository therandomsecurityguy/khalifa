module.exports = {
  plugins: {
    // Tailwind v4 moved the PostCSS plugin into @tailwindcss/postcss; the
    // package itself is no longer a PostCSS plugin.
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
};
