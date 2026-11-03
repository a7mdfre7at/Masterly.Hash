# Masterly.Hash brand notes

**The mark:** a hash sign (#) whose top bar dips into a V, making an M. All four bar overhangs
and all four stem ends are the same length, and every bar end is cut parallel to the stems.
Do not add anything to the shape or remove anything from it.

## Palette
| Token | Hex | Use |
|---|---|---|
| `brand` | `#8217D3` | Mark and `.Hash` on light backgrounds (6.97:1 on #fff) |
| `brand-dark` | `#C688FC` | Mark and `.Hash` on dark backgrounds (7.51:1 on #0d1117) |
| `tile-start` → `tile-end` | `#9C3CF0` → `#5410A6` | The one gradient in the system: icon and favicon tiles only |
| `ink` / `ink-dark` | `#16112A` / `#F3F0FA` | Wordmark "Masterly" |
| `muted` / `muted-dark` | `#4E4A66` / `#B4AFCB` | Tagline |
| `code` / `code-dark` | `#5F5A7E` / `#A29DBF` | Format line (`$` delimiters use the brand colour) |
| `panel` / `panel-dark` | `#F8F6FD` / `#13111F` | Banner and card backgrounds (borders `#E7DFF5` / `#2A2342`) |

Never use `brand` on a dark background (2.7:1) or `brand-dark` on a light one.

## Type (all SIL OFL; shipped as outlines)
- Wordmark: Space Grotesk Bold, tracking -0.02em. "Masterly" in ink, ".Hash" in brand.
- Tagline: Inter Medium. Use a typographic apostrophe: can’t.
- Format line: JetBrains Mono Medium, `$mh$p=2026a$…`. Never set it smaller than 13 px as displayed.

## Clear space and minimum size
- Leave clear space on every side equal to one overhang (about 12% of the mark's width).
- Lockups (banner, social card): the mark's ink runs from the wordmark's cap top to the last baseline of the
  text block, and the gap between mark and wordmark is about 0.77× the cap height.
- Each size range has one file:

| Displayed size | Bare mark | Tile |
|---|---|---|
| 32 px and up | `mark-light.svg` / `mark-dark.svg` | `icon.svg` / `icon.png` |
| 16-31 px | `mark-small-light.svg` / `mark-small-dark.svg` | `favicon.svg` (`favicon.ico` for legacy browsers) |

- `mark-small*.svg` and `favicon.svg` carry two cuts and pick one by their own rendered size: at 20 px and
  below they draw the pixel-hinted 16 px grid (`shape-rendering="crispEdges"`), above 20 px the thin optical cut.
  This works when the file is loaded as an image (favicon, `<img>`, Markdown, `<picture>`). Inlined in HTML the
  media query sees the page width, so the thin cut always shows; inline use below 24 px is not supported.
- The 16 px grid is not a scaled-down outline. It keeps the slant as one-pixel steps (the left stem steps once
  below the V, the right stem once below the lower bar); a second step would close a counter.

## Which file goes where
| File | Use |
|---|---|
| `mark.svg` (same as `mark-light.svg`), `mark-dark.svg` | Standalone symbol for light or dark backgrounds |
| `mark-small-light.svg`, `mark-small-dark.svg` | Small cut (16-31 px) for light or dark backgrounds |
| `mark-mono.svg` | `currentColor`, for inline SVG and CSS masks only (see note) |
| `mark-small.svg` | `currentColor` small cut, inline SVG and CSS masks only (see note) |
| `mark-white.svg` | Reversed, for photos and dark imagery |
| `icon.png` (256), `icon-128.png` | NuGet `<PackageIcon>`; the same file for all 15 packages (see below) |
| `icon.svg`, `icon-flat.svg` | App tile; gradient-free tile |
| `icon-mono.svg` | `currentColor` knockout tile, inline SVG and CSS masks only (see note) |
| `favicon.svg`, `favicon.ico` (16/32/48), `favicon-16.png`, `favicon-32.png` | Docs site and browser tabs. The 16 and 32 px frames are hand-hinted |
| `banner-light.svg` / `banner-dark.svg` | README header (switch with `<picture>`, below) |
| `banner.png` (2560×640, from `banner-light.svg`) | NuGet package READMEs, which cannot use relative paths, SVG themes or `<picture>` |
| `social-preview.png` (from `social-preview.svg`) | GitHub social preview (1280×640) |

**`currentColor` note.** `mark-mono.svg`, `mark-small.svg` and `icon-mono.svg` take their colour from CSS `color`
only when the SVG is inlined in HTML or used as a CSS `mask-image`. Loaded through `<img>`, Markdown `![]()`,
`<picture>`, nuget.org or a docs-site image tag they cannot see the page's CSS and render black, which disappears
on dark themes. In those places use the fixed-colour `-light` / `-dark` files with a `<picture>` switch.

Every SVG has `width`/`height` (512×512 for marks, icons and favicons; 1280×320 for banners; 1280×640 for the card)
as well as a `viewBox`, so a sizeless `<img>` gets a sensible default and still scales. Set `width` when embedding.

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
  <img alt="Masterly.Hash: password hashing you can’t get wrong." src="assets/banner-light.svg" width="100%">
</picture>
```

## Do not
- Recolour the mark outside the tokens above. Do not add gradients, shadows, outlines or glows to the bare mark.
- Rotate, flip or skew the mark, or change its slant. It is drawn at a 0.18 slant.
- Separate the V from the bars, or draw the top bar straight across (that turns it back into a plain #).
- Put the mark in a padlock, shield or key, or next to currency symbols.
- Retype the wordmark in a live font. Use the outlined files.
- Place `brand` violet beside Kotlin's `#7F52FF` in co-branded material without checking that the two are clearly distinguishable.

## Snippets
README banner (above). Standalone mark in a README, issue or docs page:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/mark-dark.svg">
  <img alt="Masterly.Hash" src="assets/mark-light.svg" width="64" height="64">
</picture>
```

Small mark next to text (16-31 px), same pattern with `mark-small-dark.svg` / `mark-small-light.svg` and `width="20"`.

Docs-site favicon (`<head>`):

```html
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
```

## Where the repo uses these
- **NuGet icon:** `src/Directory.Build.props` packs `assets/icon.png` into every package as `<PackageIcon>icon.png</PackageIcon>`.
- **README header:** the root `README.md` switches `banner-light.svg` / `banner-dark.svg` with `<picture>`.
- **NuGet README header:** every `src/*/README.md` starts with `banner.png` from `raw.githubusercontent.com/.../master/assets/banner.png`.
- **GitHub social preview:** not stored in git. Render `social-preview.png` (see Rebuilding) and upload it under
  repository *Settings → General → Social preview*.

Only `icon.png` and `banner.png` are committed as rasters, because NuGet needs a PNG icon and nuget.org READMEs load images from an absolute `raw.githubusercontent.com` URL. `icon-128.png`, `favicon-16.png`,
`favicon-32.png`, `favicon.ico` and `social-preview.png` are build outputs, ignored by `assets/.gitignore`.

## Rebuilding
Sources live in `src/` (`params.json` holds every number). `cd src && npm install && node build.mjs` rebuilds all
SVGs, including `src/favicon-16-pixel.svg` and `src/favicon-32-hinted.svg`. `bash render-png.sh` then renders
`icon.png`, `icon-128.png`, `favicon-16.png`, `favicon-32.png`, `social-preview.png` and `favicon.ico`
(needs Google Chrome at the path in `render.sh`). `node_modules/` is git-ignored.
