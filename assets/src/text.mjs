import {execFileSync} from 'child_process';
import {fileURLToPath} from 'url';
// text2path.mjs ships next to this file; fonts resolve from ./node_modules/@fontsource (see package.json)
const TOOL=fileURLToPath(new URL('./text2path.mjs',import.meta.url));
// compact path: absolute coords snapped to 0.1, emitted as relative commands (no cumulative drift)
export function compact(d,ox=0,oy=0){
  const tok=d.match(/[MLQCZ]|-?\d*\.?\d+(?:e-?\d+)?/gi); let i=0,out='',cx=0,cy=0,sx=0,sy=0,last='';
  const num=v=>{const s=(v/10).toString();return s.replace(/^0\./,'.').replace(/^-0\./,'-.');};
  const join=a=>a.map((v,j)=>{const s=num(v);return (j===0||s[0]==='-')?s:' '+s;}).join('');
  while(i<tok.length){const c=tok[i++].toUpperCase(); if(c==='Z'){out+='z';cx=sx;cy=sy;last='z';continue;}
    const n={M:2,L:2,Q:4,C:6}[c]; const v=tok.slice(i,i+n).map(Number); i+=n;
    const q=[];for(let j=0;j<n;j+=2){q.push(Math.round((v[j]+ox)*10),Math.round((v[j+1]+oy)*10));}
    const rel=q.map((u,j)=>u-(j%2?cy:cx));
    const cmd=c.toLowerCase(); let s=join(rel); if(cmd===last&&cmd!=='m'){if(s[0]!=='-')s=' '+s;}else s=cmd+s; out+=s; last=cmd==='m'?'l':cmd;
    cx=q[n-2];cy=q[n-1]; if(c==='M'){sx=cx;sy=cy;}}
  return out;}
export function text(fam,w,sz,ls,s){return JSON.parse(execFileSync('node',[TOOL,fam,String(w),String(sz),String(ls),s]).toString());}
