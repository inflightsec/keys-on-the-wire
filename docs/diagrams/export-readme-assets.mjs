#!/usr/bin/env node
// Extract README-ready static assets from an Archify-delivered diagram.
//
// Archify delivers a self-contained interactive HTML viewer. GitHub READMEs can
// only show static images, so this pulls the inline <svg> out of that viewer,
// re-hosts it with the viewer's own stylesheet, and renders it with headless
// Chromium at 2x. The diagram is byte-for-byte the delivered one; only the
// surrounding viewer chrome is dropped.
//
// Usage: node export-readme-assets.mjs <delivered.html> [--out-dir dir]

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const CHROME = process.env.ARCHIFY_CHROME || '/usr/bin/chromium';
const THEMES = ['light', 'dark'];

function parseArgs(argv) {
  const [input, ...rest] = argv;
  if (!input) {
    console.error('usage: export-readme-assets.mjs <delivered.html> [--out-dir dir]');
    process.exit(2);
  }
  let outDir = path.dirname(path.resolve(input));
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === '--out-dir') {
      outDir = path.resolve(rest[i + 1]);
      i += 1;
    } else {
      console.error(`unknown option: ${rest[i]}`);
      process.exit(2);
    }
  }
  return { input: path.resolve(input), outDir };
}

function extract(html) {
  const svg = html.match(/<svg[\s\S]*?<\/svg>/);
  const style = html.match(/<style[^>]*>([\s\S]*?)<\/style>/);
  if (!svg) throw new Error('no <svg> block found — is this an Archify-delivered artifact?');
  if (!style) throw new Error('no <style> block found — is this an Archify-delivered artifact?');
  const viewBox = svg[0].match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
  if (!viewBox) throw new Error('svg has no parseable viewBox');
  return {
    svg: svg[0],
    css: style[1],
    width: Math.ceil(Number(viewBox[1])),
    height: Math.ceil(Number(viewBox[2])),
  };
}

// The viewer scopes its CSS custom properties to [data-theme] on <html> and
// styles the diagram through .diagram-container, so both must be reproduced.
function wrapperHtml({ svg, css, width, height }, theme) {
  return `<!doctype html>
<html lang="en" data-theme="${theme}" data-preset="classic">
<head><meta charset="utf-8"><style>${css}</style>
<style>
  html, body { margin: 0; padding: 0; background: var(--bg); }
  .diagram-container { width: ${width}px; height: ${height}px; }
  .diagram-container svg { display: block; width: ${width}px; height: ${height}px; }
</style></head>
<body><div class="diagram-container" data-detail-level="read">${svg}</div></body>
</html>`;
}

// The viewer stylesheet also dresses the surrounding app chrome, which a
// standalone SVG has none of. Keep the custom-property blocks, the animation
// and font definitions, and only those rules whose selector names a class the
// SVG actually uses. Anything unmatched is app chrome and is dropped.
function slimCss(css, svg) {
  const used = new Set();
  for (const attr of svg.match(/class="[^"]*"/g) || []) {
    for (const cls of attr.slice(7, -1).split(/\s+/)) if (cls) used.add(cls);
  }
  const keptAtRule = /^@(font-face|keyframes|-webkit-keyframes|property)/;
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1;
    else if (css[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        const block = css.slice(start, i + 1).trim();
        start = i + 1;
        if (!block) continue;
        const selector = block.slice(0, block.indexOf('{')).trim();
        const classes = selector.match(/\.[A-Za-z0-9_-]+/g) || [];
        const keep =
          keptAtRule.test(selector) ||
          selector.includes(':root') ||
          selector.includes('[data-theme') ||
          // Element- and id-only rules carry the primitive shape styling
          // (rect, line, text, markers); they have no class to match against.
          classes.length === 0 ||
          classes.some((c) => used.has(c.slice(1)));
        if (keep) out.push(block);
      }
    }
  }
  return out.join('\n');
}

function standaloneSvg({ svg, css, width, height }, theme) {
  const style = slimCss(css, svg);
  const rooted = svg
    .replace(/^<svg /, `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" data-theme="${theme}" `)
    // The stylesheet is XML character data: it carries `<` inside comments and
    // would otherwise be parsed as markup by a strict SVG reader.
    // A standalone SVG has no page behind it, so the theme background has to be
    // painted by the root element itself.
    .replace(/^(<svg[^>]*>)/, `$1<style><![CDATA[\n:root{background:var(--bg);}\n${style}\n]]></style>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n${rooted}`;
}

function shoot(chrome, htmlPath, pngPath, width, height) {
  const profile = mkdtempSync(path.join(tmpdir(), 'archify-shot-'));
  const res = spawnSync(chrome, [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    '--hide-scrollbars',
    `--user-data-dir=${profile}`,
    `--force-device-scale-factor=2`,
    `--window-size=${width},${height}`,
    `--screenshot=${pngPath}`,
    `file://${htmlPath}`,
  ], { encoding: 'utf8', timeout: 120_000 });
  if (res.status !== 0 || !existsSync(pngPath)) {
    throw new Error(`chromium screenshot failed (${res.status}): ${res.stderr?.slice(0, 400)}`);
  }
}

const { input, outDir } = parseArgs(process.argv.slice(2));
const parts = extract(readFileSync(input, 'utf8'));
const base = path.basename(input, '.html');
const scratch = mkdtempSync(path.join(tmpdir(), 'archify-export-'));
const written = [];

for (const theme of THEMES) {
  const htmlPath = path.join(scratch, `${base}.${theme}.html`);
  writeFileSync(htmlPath, wrapperHtml(parts, theme));

  const svgPath = path.join(outDir, `${base}.${theme}.svg`);
  writeFileSync(svgPath, standaloneSvg(parts, theme));
  written.push(svgPath);

  const pngScratch = path.join(scratch, `${base}.${theme}.png`);
  shoot(CHROME, htmlPath, pngScratch, parts.width, parts.height);
  const pngPath = path.join(outDir, `${base}.${theme}.png`);
  copyFileSync(pngScratch, pngPath);
  written.push(pngPath);
}

console.log(JSON.stringify({
  ok: true,
  input,
  viewBox: [parts.width, parts.height],
  themes: THEMES,
  written,
}, null, 2));
