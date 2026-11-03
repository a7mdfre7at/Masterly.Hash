#!/usr/bin/env bash
# Renders the PNG and ICO files from the SVGs built by build.mjs (needs Google Chrome; see render.sh).
set -euo pipefail
cd "$(dirname "$0")"; R="bash ./render.sh"; O=..
$R $O/icon.svg               $O/icon.png            256 256
$R $O/icon.svg               $O/icon-128.png        128 128
$R favicon-16-pixel.svg      $O/favicon-16.png       16  16
$R favicon-32-hinted.svg     $O/favicon-32.png       32  32
$R $O/favicon.svg            favicon-48.tmp.png      48  48
$R $O/social-preview.svg     $O/social-preview.png 1280 640
node ico.mjs $O/favicon-16.png $O/favicon-32.png favicon-48.tmp.png $O/favicon.ico
rm -f favicon-48.tmp.png
