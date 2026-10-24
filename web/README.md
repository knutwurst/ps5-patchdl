# web

The UI PatchDL serves on port 12880. Plain HTML, CSS and JS, no build step.

At build time `scripts/gen_asset_module.py` turns `index.html`, `styles.css`,
`i18n.js` and `app.js` into C arrays under `gen/web/`, so the ELF carries the
whole UI.

Opening `index.html` straight from disk works too. Without the API behind it,
the page falls back to demo data, which is handy for fiddling with the layout.

Texts live in `i18n.js`, ten languages. New strings go into English first; a
missing key falls back to English.
