// Pixel-hinted 16 px cut of the mark, drawn on a 16x16 grid (1 cell = 32 units of the 512 box).
// Stems are 2 px, bars 1 px. The slant is expressed as one-pixel steps: the left stem steps left
// below the V, the right stem steps left below the lower bar (stepping it earlier would close the
// right counter). build.mjs uses it for favicon.svg, mark-small*.svg and src/favicon-16-pixel.svg.
export const GRID16=[
"................",
"................",
"................",
".....##....##...",
".....##....##...",
"...####....####.",
".....###..###...",
"....##.#.#.##...",
"....##.#.#.##...",
"....##..#..##...",
"..############..",
"....##....##....",
"....##....##....",
"................",
"................",
"................"];
// one rect per horizontal run, in 512-box units
export function pixPath(g=GRID16,cell=32){let d='';g.forEach((row,y)=>{let x=0;while(x<row.length){if(row[x]==='#'){let e=x;while(row[e]==='#')e++;
  d+=`M${x*cell} ${y*cell}h${(e-x)*cell}v${cell}h${-(e-x)*cell}z`;x=e;}else x++;}});return d;}
