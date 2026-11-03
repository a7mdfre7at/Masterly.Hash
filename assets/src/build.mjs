// Rebuilds every SVG in the asset folder (the parent of this folder) from params.json.
// Usage: npm install && node build.mjs   (then ./render-png.sh for the PNG and ICO files)
import fs from 'fs'; import {fileURLToPath} from 'url'; import pc from 'polygon-clipping';
import {hashM,toD,roundRect} from './geom.mjs'; import {text,compact} from './text.mjs'; import {pixPath} from './pix.mjs';
const HERE=fileURLToPath(new URL('.',import.meta.url)); const OUT=fileURLToPath(new URL('..',import.meta.url));
const P=JSON.parse(fs.readFileSync(`${HERE}/params.json`,'utf8')); const C=P.color;
const M=hashM(P.master), F=hashM(P.favicon);
console.log('master bbox',M.bbox.map(v=>+v.toFixed(1)),'favicon bbox',F.bbox.map(v=>+v.toFixed(1)));
const TITLE='Masterly.Hash';
// width/height give a sensible intrinsic size for a sizeless <img> or Markdown image; the viewBox keeps it scalable
const svg=(vb,body,title=TITLE)=>{const [,,w,h]=vb.split(' ');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="${vb}" role="img" aria-label="${title}"><title>${title}</title>${body}</svg>\n`;};
const W=(f,s,dir=OUT)=>{fs.writeFileSync(`${dir}/${f}`,s);};
const MD=toD(M.mp), FD=toD(F.mp);
const sc=(g,k)=>toD(g.mp,k,256-256*k,256-256*k);
// Size switch for files that carry two cuts. Inside an SVG loaded as an image (favicon, <img>, Markdown) the media
// query sees the rendered image size, so the pixel-hinted 16 px cut shows at <= breakpoint and the smooth cut above it.
// Inlined in an HTML page it sees the page viewport, so the smooth cut always shows. Class names are namespaced.
const BP=P.pixel.breakpoint;
const RESP=`<style>.mh-px{display:none}@media (max-width:${BP}px){.mh-px{display:inline}.mh-sm{display:none}}</style>`;
const PX=pixPath();
const pxPath=fill=>`<path class="mh-px" fill="${fill}" shape-rendering="crispEdges" d="${PX}"/>`;
const grad=id=>`<defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${C.grad0}"/><stop offset="1" stop-color="${C.grad1}"/></linearGradient></defs>`;
const tile=(fill,rx)=>`<rect width="512" height="512" rx="${rx}" fill="${fill}"/>`;
// ---- marks ----
W('mark.svg',svg('0 0 512 512',`<path fill="${C.brand}" d="${MD}"/>`));
W('mark-light.svg',svg('0 0 512 512',`<path fill="${C.brand}" d="${MD}"/>`));
W('mark-dark.svg',svg('0 0 512 512',`<path fill="${C.brandDark}" d="${MD}"/>`));
W('mark-mono.svg',svg('0 0 512 512',`<path fill="currentColor" d="${MD}"/>`));
W('mark-white.svg',svg('0 0 512 512',`<path fill="#FFFFFF" d="${MD}"/>`));
// small cut: thin optical cut, switching to the pixel-hinted grid at <= BP px
const small=fill=>svg('0 0 512 512',RESP+`<path class="mh-sm" fill="${fill}" d="${FD}"/>`+pxPath(fill));
W('mark-small.svg',small('currentColor'));
W('mark-small-light.svg',small(C.brand));
W('mark-small-dark.svg',small(C.brandDark));
// ---- icons ----
W('icon.svg',svg('0 0 512 512',grad('mh-icon-tile')+tile('url(#mh-icon-tile)',P.icon.rx)+`<path fill="#FFFFFF" d="${sc(M,P.icon.scale)}"/>`));
W('icon-flat.svg',svg('0 0 512 512',tile(C.brand,P.icon.rx)+`<path fill="#FFFFFF" d="${sc(M,P.icon.scale)}"/>`));
// true knockout: one path, tile minus mark (no masks), single colour
const k=P.icon.scale, ko=pc.difference(roundRect(512,512,P.icon.rx,16),M.mp.map(p=>p.map(r=>r.map(([x,y])=>[x*k+256-256*k,y*k+256-256*k]))));
W('icon-mono.svg',svg('0 0 512 512',`<path fill="currentColor" d="${toD(ko)}"/>`));
// ---- favicons ----
const FT=P.faviconTile;
W('favicon.svg',svg('0 0 512 512',RESP+grad('mh-favicon-tile')+tile('url(#mh-favicon-tile)',FT.rx)+
  `<path class="mh-sm" fill="#FFFFFF" d="${sc(F,FT.scale)}"/>`+pxPath('#FFFFFF')));
// 16 px raster source: the pixel grid alone
W('favicon-16-pixel.svg',svg('0 0 512 512',grad('mh-favicon16-tile')+tile('url(#mh-favicon16-tile)',FT.rx)+
  `<path fill="#FFFFFF" shape-rendering="crispEdges" d="${PX}"/>`),HERE);
// 32 px raster source: every horizontal edge (stem ends, bar edges) moved onto the 16-unit (1 px at 32 px) grid
// by a piecewise-linear remap of y. Slanted stem edges keep their anti-aliasing; nothing else changes.
{const g=F.mp.map(p=>p.map(r=>r.map(([x,y])=>[x*FT.scale+256-256*FT.scale,y*FT.scale+256-256*FT.scale])));
 const ys=[...new Set(g.flat(2).map(q=>+q[1].toFixed(1)))].sort((a,b)=>a-b);
 const tp=ys[0], bt=ys.at(-1), keys=[tp, F.ya*FT.scale+256-256*FT.scale, F.yb*FT.scale+256-256*FT.scale, bt];
 const half=P.favicon.t*FT.scale/2; const src=[keys[0],keys[1]-half,keys[1]+half,keys[2]-half,keys[2]+half,keys[3]];
 const dst=P.hint32.y; console.log('hint32',src.map(v=>+v.toFixed(1)),'->',dst);
 const remap=y=>{let i=0;while(i<src.length-2&&y>src[i+1])i++;return dst[i]+(y-src[i])*(dst[i+1]-dst[i])/(src[i+1]-src[i]);};
 const h=g.map(p=>p.map(r=>r.map(([x,y])=>[x,remap(y)])));
 W('favicon-32-hinted.svg',svg('0 0 512 512',grad('mh-favicon32-tile')+tile('url(#mh-favicon32-tile)',FT.rx)+
  `<path fill="#FFFFFF" d="${toD(h)}"/>`),HERE);}
// ---- type ----
const B=P.banner;
const word=(sz)=>{const a=text('space-grotesk',700,sz,B.wls,'Masterly'),b=text('space-grotesk',700,sz,B.wls,'.Hash');return {a,b,w:a.width+B.kern*sz/92+b.width};};
const codeRuns=(sz,str)=>{const delim=[...str].map(ch=>ch==='$'?'$':' ').join(''), rest=[...str].map(ch=>ch==='$'?' ':ch).join('');
  const d=text('jetbrains-mono',500,sz,0,delim), r=text('jetbrains-mono',500,sz,0,rest);return {d,r,w:r.width};};
const run=(fill,j,x,y)=>`<path fill="${fill}" d="${compact(j.d,x,y)}"/>`;
// conservative ink box of an absolute text path (control points included)
const box=d=>{const n=d.match(/-?\d*\.?\d+(?:e-?\d+)?/gi).map(Number);const xs=n.filter((_,i)=>i%2===0),ys=n.filter((_,i)=>i%2===1);
  return [Math.min(...xs),Math.min(...ys),Math.max(...xs),Math.max(...ys)];};
// lockup rule (banner and card): the mark's ink spans the wordmark cap top to the last baseline of the text block,
// and the gap between mark ink and wordmark ink is a fixed fraction of the cap height
const capOf=sz=>{const b=box(text('space-grotesk',700,sz,B.wls,'M').d);return {cap:-b[1],lsb:b[0]};};
const INK_H=M.bbox[3]-M.bbox[1], INK_W=M.bbox[2]-M.bbox[0];
// memory-block motif: Argon2 fills its matrix block by block; rows filled, one current block, rest empty
function lattice(x0,y0,mode,opt={}){const c=C[mode];const cols=opt.cols??5,rows=opt.rows??6,bw=opt.bw??30,bh=opt.bh??17,gx=opt.gx??8,gy=opt.gy??9,s=P.master.s;
  const cur=[rows-2,2]; let filled='',empty='',hot='';
  for(let r=0;r<rows;r++)for(let q=0;q<cols;q++){const y=y0+r*(bh+gy), sh=(y0+rows*(bh+gy)-y)*s, x=x0+q*(bw+gx)+sh;
    const p=`M${(x+bh*s).toFixed(1)} ${y}h${bw}l${(-bh*s).toFixed(1)} ${bh}h${-bw}z`;
    const done=r<cur[0]||(r===cur[0]&&q<cur[1]);
    if(r===cur[0]&&q===cur[1])hot+=p; else if(done)filled+=p; else empty+=p;}
  const fo=mode==='light'?0.12:0.2;
  return `<path fill="${c.block}" fill-opacity="${fo}" d="${filled}"/><path fill="none" stroke="${c.block}" stroke-opacity="${mode==='light'?0.24:0.3}" stroke-width="1.5" d="${empty}"/><path fill="${c.block}" d="${hot}"/>`;}
// ---- banners ----
const w=word(B.wsize), tg=text('inter',500,B.tsize,0,'Password hashing you can’t get wrong.'), cd=codeRuns(B.csize,B.code);
const bc=capOf(B.wsize), mk=B.mark/512;
const GAP_RATIO=((B.tx+bc.lsb)-(B.mx+M.bbox[2]*mk))/bc.cap;
console.log('banner: word end',(B.tx+w.w).toFixed(0),'tag end',(B.tx+4+tg.width).toFixed(0),'code end',(B.tx+4+cd.w).toFixed(0),
  '| mark ink y',(B.my+M.bbox[1]*mk).toFixed(1),'-',(B.my+M.bbox[3]*mk).toFixed(1),'cap top',(B.wy-bc.cap).toFixed(1),'gap/cap',GAP_RATIO.toFixed(3));
const banner=mode=>{const c=C[mode]; const acc=mode==='light'?C.brand:C.brandDark;
 return svg('0 0 1280 320',
  `<rect x=".5" y=".5" width="1279" height="319" rx="${B.rx}" fill="${c.panel}" stroke="${c.stroke}"/>`+
  `<path fill="${acc}" d="${toD(M.mp,mk,B.mx,B.my)}"/>`+
  run(c.word,w.a,B.tx,B.wy)+run(acc,w.b,B.tx+w.a.width+B.kern,B.wy)+
  run(c.tag,tg,B.tx+4,B.ty)+run(c.code,cd.r,B.tx+4,B.cy)+run(acc,cd.d,B.tx+4,B.cy)+
  lattice(B.lx,B.ly,mode),
  'Masterly.Hash — Password hashing you can’t get wrong.');};
W('banner-light.svg',banner('light')); W('banner-dark.svg',banner('dark'));
// ---- social preview 1280x640 (opaque, content inside 80px safe area) ----
{const S=P.social, c=C.dark, acc=C.brandDark;
 const w2=word(S.wsize), t2=text('inter',500,S.tsize,0,'Password hashing you can’t get wrong.'), c2=codeRuns(S.csize,B.code);
 const sc2=capOf(S.wsize), tagDy=Math.round(S.tagDy), ms=(sc2.cap+tagDy)*512/INK_H, k2=ms/512;
 const gapInk=GAP_RATIO*sc2.cap, textInkR=Math.max(w2.w, S.tagDx+box(t2.d)[2]), textInkW=textInkR-sc2.lsb;
 const totalInk=INK_W*k2+gapInk+textInkW, inkL=(1280-totalInk)/2, inkR=inkL+totalInk;
 const x0=inkL-M.bbox[0]*k2, tx=inkL+INK_W*k2+gapInk-sc2.lsb;
 // vertical: cap top .. code-line ink bottom, centred on the card
 const codeBox=box(c2.r.d), codeBot=Math.max(codeBox[3],box(c2.d.d)[3]);
 const blockH=sc2.cap+tagDy+S.ruleGap+S.codeGap+codeBot, capTop=(640-blockH)/2;
 const bl=capTop+sc2.cap, my=capTop-M.bbox[1]*k2, ruleY=Math.round(bl+tagDy+S.ruleGap), codeBl=ruleY+S.codeGap;
 console.log('social: mark',ms.toFixed(1),'ink x',inkL.toFixed(1),'-',inkR.toFixed(1),'y',capTop.toFixed(1),'-',(codeBl+codeBot).toFixed(1),'rule',ruleY);
 W('social-preview.svg',svg('0 0 1280 640',
  `<rect width="1280" height="640" fill="${c.panel}"/>`+
  `<path fill="${acc}" d="${toD(M.mp,k2,x0,my)}"/>`+
  run(c.word,w2.a,tx,bl)+run(acc,w2.b,tx+w2.a.width+B.kern*S.wsize/92,bl)+
  run(c.tag,t2,tx+S.tagDx,bl+tagDy)+
  `<path fill="none" stroke="${c.stroke}" stroke-width="2" d="M${Math.round(inkL)} ${ruleY}H${Math.round(inkR)}"/>`+
  run(c.code,c2.r,640-c2.w/2,codeBl)+run(acc,c2.d,640-c2.w/2,codeBl),
  'Masterly.Hash — Password hashing you can’t get wrong.'));}
for(const f of fs.readdirSync(OUT).filter(f=>f.endsWith('.svg')))console.log(f.padEnd(22),fs.statSync(`${OUT}/${f}`).size);
