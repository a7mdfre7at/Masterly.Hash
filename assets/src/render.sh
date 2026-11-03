#!/usr/bin/env bash
# usage: render.sh <in.svg> <out.png> <width> <height>
# Renders an SVG to PNG with a transparent background via headless Chrome.
set -euo pipefail
IN="$(cygpath -w "$(realpath "$1")")"; OUT="$(cygpath -w "$(realpath -m "$2")")"; W="$3"; H="$4"
TMP="$(mktemp -d)"; HTML="$TMP/page.html"
SVG="$(cat "$1")"
cat > "$HTML" <<HTML
<!doctype html><html><head><style>html,body{margin:0;padding:0;background:transparent;overflow:hidden}svg{display:block;width:${W}px;height:${H}px}</style></head><body>$SVG</body></html>
HTML
"/c/Program Files/Google/Chrome/Application/chrome.exe" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --default-background-color=00000000 --window-size="$W,$H" --screenshot="$OUT" "file:///$(cygpath -m "$HTML")" >/dev/null 2>&1
rm -rf "$TMP"; echo "rendered $OUT"
