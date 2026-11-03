import pc from 'polygon-clipping';
// Hash-M construction. All "arms" of the # (4 bar overhangs + 4 stem ends) share one length `arm`.
// p: {t, tv, s, gap, k, arm}  t=stem/bar thickness, tv=V-arm thickness, s=slant, gap=stem centre spacing,
// k=bar centre offset from y=256, arm=overhang length past stem outer edge (and stem length past bar edge)
export function hashM(p){
  const {t,tv,s,gap,k,arm}=p; const ya=256-k, yb=256+k;
  const top=ya-t/2-arm, bot=yb+t/2+arm;
  const hw=t/2*Math.hypot(1,s);
  const xl=y=>256-gap/2+(256-y)*s, xr=y=>256+gap/2+(256-y)*s;
  const quad=(a,b,c,d)=>[[a,b,c,d,a]];
  const stem=x=>quad([x(top)-hw,top],[x(top)+hw,top],[x(bot)+hw,bot],[x(bot)-hw,bot]);
  // bar ends are cut parallel to the stems, so every overhang is the same parallelogram as its neighbours
  const e=t/2*s; const hbar=(x0,x1,y)=>quad([x0+e,y-t/2],[x1+e,y-t/2],[x1-e,y+t/2],[x0-e,y+t/2]);
  const band=(a,b,w)=>{const dx=b[0]-a[0],dy=b[1]-a[1],L=Math.hypot(dx,dy),nx=-dy/L*w/2,ny=dx/L*w/2;
    return quad([a[0]+nx,a[1]+ny],[b[0]+nx,b[1]+ny],[b[0]-nx,b[1]-ny],[a[0]-nx,a[1]-ny]);};
  // apex: on the slanted axis, at the lower bar centre line, so the V merges fully into the bar (no residual slivers)
  const ay=yb+(p.apexDY??0); const apex=[(xl(ay)+xr(ay))/2, ay];
  // arms start at the stem centre line on the top bar centre; extend a little past so the join is solid
  const aL=[xl(ya),ya], aR=[xr(ya),ya];
  const ext=(a,b,e)=>{const dx=b[0]-a[0],dy=b[1]-a[1],L=Math.hypot(dx,dy);return [b[0]+dx/L*e,b[1]+dy/L*e];};
  const parts=[stem(xl),stem(xr),
    hbar(xl(ya)-hw-arm, xl(ya), ya), hbar(xr(ya), xr(ya)+hw+arm, ya),   // top bar: only the two outer pieces
    hbar(xl(yb)-hw-arm, xr(yb)+hw+arm, yb),                              // lower bar: straight, full
    ...pc.intersection(pc.union(band(aL,apex,tv),band(aR,apex,tv)),quad([-1e3,top],[1e3,top],[1e3,yb+t/2],[-1e3,yb+t/2]))];
  let u=pc.union(...parts);
  // clip anything of the V that pokes below the lower bar
  u=pc.intersection(u,[[[-1e3,top],[1e3,top],[1e3,bot],[-1e3,bot],[-1e3,top]]]);
  // centre in 512 box
  const pts=u.flat(2); const xs=pts.map(q=>q[0]), ys=pts.map(q=>q[1]);
  const bx=[Math.min(...xs),Math.max(...xs)], by=[Math.min(...ys),Math.max(...ys)];
  const dx=256-(bx[0]+bx[1])/2, dy=256-(by[0]+by[1])/2;
  u=u.map(poly=>poly.map(ring=>ring.map(([x,y])=>[x+dx,y+dy])));
  return {mp:u, bbox:[bx[0]+dx,by[0]+dy,bx[1]+dx,by[1]+dy], ya:ya+dy, yb:yb+dy};
}
const r1=v=>{const r=Math.round(v*10)/10;return Object.is(r,-0)?0:r;};
export const toD=(mp,scale=1,ox=0,oy=0)=>mp.map(poly=>poly.map(ring=>{
  const pts=ring.slice(0,-1).map(([x,y])=>[r1(x*scale+ox),r1(y*scale+oy)]);
  return 'M'+pts.map(q=>q.join(' ')).join('L')+'Z';}).join('')).join('');
// tile path (rounded rect) as polygon for knockouts
export function roundRect(w,h,r,n=12){const ring=[];const c=[[w-r,r,-90],[w-r,h-r,0],[r,h-r,90],[r,r,180]];
  for(const [cx,cy,a0] of c)for(let i=0;i<=n;i++){const a=(a0+90*i/n)*Math.PI/180;ring.push([cx+r*Math.cos(a),cy+r*Math.sin(a)]);}
  ring.push(ring[0]);return [[ring]];}
