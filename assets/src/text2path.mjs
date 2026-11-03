// usage: node text2path.mjs <family> <weight> <fontSizePx> <letterSpacingEm> "<text>"
// family: inter | space-grotesk | jetbrains-mono | manrope | sora
// Prints JSON {d, width, ascender, descender} — an SVG path with baseline at y=0, x starting at 0.
import opentype from 'opentype.js';
import { fileURLToPath } from 'url'; import path from 'path'; import fs from 'fs';
const [family, weight, size, ls, text] = process.argv.slice(2);
const dir = path.dirname(fileURLToPath(import.meta.url));
const file = path.join(dir, 'node_modules/@fontsource', family, 'files', `${family}-latin-${weight}-normal.woff`);
if (!fs.existsSync(file)) { console.error('missing font ' + file); process.exit(1); }
const font = opentype.loadSync(file);
const fs_ = Number(size), spacing = Number(ls || 0) * fs_;
let x = 0; const parts = [];
const glyphs = font.stringToGlyphs(text);
glyphs.forEach((g, i) => {
  parts.push(g.getPath(x, 0, fs_).toPathData(2));
  x += g.advanceWidth * fs_ / font.unitsPerEm;
  if (i < glyphs.length - 1) x += font.getKerningValue(g, glyphs[i + 1]) * fs_ / font.unitsPerEm + spacing;
});
console.log(JSON.stringify({ d: parts.join(''), width: +x.toFixed(2), ascender: font.ascender * fs_ / font.unitsPerEm, descender: font.descender * fs_ / font.unitsPerEm }));
