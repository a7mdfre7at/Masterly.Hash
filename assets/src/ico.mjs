import fs from 'fs'; const files=process.argv.slice(2,-1), out=process.argv.at(-1);
const imgs=files.map(f=>fs.readFileSync(f)); const head=Buffer.alloc(6+16*imgs.length); head.writeUInt16LE(0,0);head.writeUInt16LE(1,2);head.writeUInt16LE(imgs.length,4);
let off=head.length; imgs.forEach((b,i)=>{const w=b.readUInt32BE(16),h=b.readUInt32BE(20);const o=6+16*i;head[o]=w>=256?0:w;head[o+1]=h>=256?0:h;head.writeUInt16LE(1,o+4);head.writeUInt16LE(32,o+6);head.writeUInt32LE(b.length,o+8);head.writeUInt32LE(off,o+12);off+=b.length;});
fs.writeFileSync(out,Buffer.concat([head,...imgs]));
