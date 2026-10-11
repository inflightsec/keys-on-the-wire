# Diagrams

Sequence diagrams for the two stories the README tells: how a credential gets
injected, and what happens when a bound key is used against an unbound method.

Each diagram is authored as typed JSON IR and compiled by
[Archify](https://github.com/tt-a1i/archify) (MIT) into a self-contained
interactive HTML viewer. `export-readme-assets.mjs` then lifts the inline SVG out
of that viewer and renders static PNG and SVG for the README.

| Source | Viewer | README assets |
|---|---|---|
| `kow-injection.sequence.json` | `kow-injection.html` | `kow-injection.{light,dark}.{png,svg}` |
| `kow-denied.sequence.json` | `kow-denied.html` | `kow-denied.{light,dark}.{png,svg}` |

## Regenerating

Archify needs no install and no network at render time. Clone it once, point
`ARCHIFY` at the package directory inside the checkout, and use Node 18+.

```bash
git clone --depth 1 https://github.com/tt-a1i/archify
ARCHIFY=$PWD/archify/archify

for n in kow-injection kow-denied; do
  node "$ARCHIFY/bin/archify.mjs" deliver sequence "$n.sequence.json" "$n.html" --quality showcase --json
  node export-readme-assets.mjs "$n.html"
done
```

`deliver` is the acceptance gate: it fails non-zero unless all nine artifact
checks pass with zero composition errors and warnings. To see the geometry
diagnostics while editing a source, use `validate` instead of `deliver`.

## Embedding

GitHub picks the variant matching the reader's theme. This is the one place
`<picture>` is needed, because Markdown image syntax cannot express a theme
switch.

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/kow-injection.dark.png">
  <img alt="How Keys on the Wire injects a credential" src="docs/diagrams/kow-injection.light.png">
</picture>
```

## Known limits

- **Use the PNG in the README.** The SVG is faithful in colour and geometry, but
  a browser will not load webfonts for an SVG referenced as an image, so type
  falls back to a system face. The PNG is rendered at 2x with the real fonts.
- The interactive viewer fits one screen at 1920x1080 and above. At 1440x900 it
  scrolls by roughly 60-95px. That affects the HTML viewer only, never the
  exported assets.
