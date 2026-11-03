export const hex2rgb=h=>[1,3,5].map(i=>parseInt(h.slice(i,i+2),16));
export const lum=h=>{const [r,g,b]=hex2rgb(h).map(v=>{v/=255;return v<=0.03928?v/12.92:((v+0.055)/1.055)**2.4});return 0.2126*r+0.7152*g+0.0722*b;};
export const cr=(a,b)=>{const [x,y]=[lum(a),lum(b)].sort((p,q)=>q-p);return (x+0.05)/(y+0.05);};
export const hsl=h=>{let [r,g,b]=hex2rgb(h).map(v=>v/255);const mx=Math.max(r,g,b),mn=Math.min(r,g,b);let H=0;const d=mx-mn;if(d){if(mx===r)H=((g-b)/d)%6;else if(mx===g)H=(b-r)/d+2;else H=(r-g)/d+4;H*=60;if(H<0)H+=360;}const L=(mx+mn)/2;const S=d?d/(1-Math.abs(2*L-1)):0;return [Math.round(H),Math.round(S*100),Math.round(L*100)];};
export const fromHsl=(H,S,L)=>{S/=100;L/=100;const k=n=>(n+H/30)%12,a=S*Math.min(L,1-L);const f=n=>L-a*Math.max(-1,Math.min(k(n)-3,9-k(n),1));return '#'+[f(0),f(8),f(4)].map(v=>Math.round(v*255).toString(16).padStart(2,'0')).join('').toUpperCase();};
