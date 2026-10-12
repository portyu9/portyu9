#!/usr/bin/env node
'use strict';
// Deterministic cinematic plasma-field GIF renderer. No line-path or stroke-dash animation.
const fs = require('node:fs');
const path = require('node:path');
const TWO=Math.PI*2;
const clamp=(x,a=0,b=1)=>x<a?a:x>b?b:x;
const smooth=x=>{x=clamp(x);return x*x*(3-2*x)};
const surfaces = { 'top':[448,90], 'top-compact':[420,128], 'bottom':[448,52] };
const PALETTE_GROUPS = [
[255,20,166],[5,216,255],[165,65,255],[0,255,186],
[236,171,252],[60,97,255],[255,102,185],[238,246,255]
];
const palette=[];
for(const rgb of PALETTE_GROUPS)for(let j=0;j<32;j++){
 const s=Math.pow(j/31,1.15);for(let k=0;k<3;k++)palette.push(Math.round(rgb[k]*s));
}
const put16=(a,x)=>{a.push(x&255,(x>>8)&255)};
function writeGIF(w,h,frames,delay){
 const o=[];const str=s=>{for(let j=0;j<s.length;j++)o.push(s.charCodeAt(j))};
 str('GIF89a');put16(o,w);put16(o,h);o.push(0xf7,0,0);o.push(...palette);
 o.push(0x21,0xff,11);str('NETSCAPE2.0');o.push(3,1,0,0,0);
 for(const frame of frames){
  o.push(0x21,0xf9,4,0);put16(o,delay);o.push(0,0);
  o.push(0x2c);put16(o,0);put16(o,0);put16(o,w);put16(o,h);o.push(0);
  o.push(8);
  const raw=[];let buf=0,nbits=0;
  const emit=(c,size)=>{buf|=c<<nbits;nbits+=size;while(nbits>=8){raw.push(buf&255);buf>>>=8;nbits-=8;}};
  let dict=new Map(),next=258;
  const reset=()=>{dict=new Map();next=258;emit(256,9)};
  reset();let p=frame[0];
  for(let i=1;i<frame.length;i++){
    const v=frame[i],key=p*256+v,found=dict.get(key);
    if(found!==undefined){p=found;continue;}
    emit(p,9);
    if(next<480){dict.set(key,next++);} else reset();
    p=v;
  }
  emit(p,9);emit(257,9);if(nbits)raw.push(buf&255);
  for(let i=0;i<raw.length;i+=255){const length=Math.min(255,raw.length-i);o.push(length);for(let j=0;j<length;j++)o.push(raw[i+j]);}
  o.push(0);
 }
 o.push(0x3b);return Buffer.from(o);
}
function render(w,h,phase){
 const pixels=new Uint8Array(w*h);
 const cx=w*.5,cy=h*.5,ys=h*.78;
 const p=Math.PI;
 for(let y=0;y<h;y++){
  const dy=y-cy;
  for(let x=0;x<w;x++){
   const dx=x-cx,u=smooth((Math.abs(dx)-h*.18)/(w*.27)),sx=h*.78+(w*.43-h*.78)*u;
   const ax=dx/sx,by=dy/ys,r=Math.sqrt(ax*ax+by*by)+.00000001;
   const theta=Math.atan2(by,ax),t=phase*TWO;
   const twist=theta+.035*Math.sin(r*8-t*.7+Math.sin(theta*12)*.6)+.025*Math.sin(theta*14-r*11+t*1.1)+.013*Math.sin(theta*38+r*9-t*2);
   const ca=Math.max(0,Math.cos(175*twist+7*Math.sin(2*r+t))),cb=Math.max(0,Math.cos(113*twist+12*r-2*t+3*Math.sin(theta*9+r*5))),cc=Math.max(0,Math.cos(211*twist-13*r+2.8*t+2*Math.sin(theta*33)));
   const f1=ca**22,f2=cb**27,f3=cc**30;
   const edge=.9+.12*Math.sin(theta*9+2*t)+.08*Math.sin(theta*17-t)+.11*Math.sin(theta*31+2*t+.6*Math.sin(r*4));
   const envelope=clamp((r-.34)/.1)*clamp((edge-r)/.17);
   const nebula=Math.exp(-Math.pow((r-.56)/.42,2))*envelope;
   const flame=Math.pow(Math.sin(theta*8.5+Math.sin(r*11+t)*1.8+Math.sin(theta*17-t*1.1)),2);
   const petals=Math.pow(Math.sin(theta*13.1+r*7.4-t*.7),2);
   const lobe=nebula*(.29+.61*flame+.22*petals);
   const near=Math.exp(-Math.pow((r-.41)/.19,2)),far=Math.exp(-Math.pow((r-.74)/.34,2));
   const violet=Math.exp(-Math.pow((r-.47)/.25,2))*envelope*(f1+f2);
   const ring=Math.exp(-Math.pow((r-.34)/.012,2))*1.9;
   let pink=(near*(f1*.65+f2*.6)+violet*.45+nebula*.24+lobe*.29)*1.3+ring;
   let cyan=(far*(f1*.9+f2*.8+f3*.4)+nebula*.17+lobe*.48)*1.4;
   if(r<.34){pink=0;cyan=0;}
   // A volumetric bloom approximation, flowing with the morphing field; never fixed-line trails.
   const glow=(Math.exp(-Math.pow((r-.43)/.12,2))*.11+nebula*.11);
   pink+=glow*(.3+.7*Math.sin(theta*7+t*.9)**2);
   cyan+=glow*(.3+.7*Math.cos(theta*11-t)**2);
   const energy=pink+cyan;
   const intensity=clamp(Math.pow(1-Math.exp(-energy*.82),.76));
   const a=pink/(energy+1e-9);
   let group;
   if(intensity>.84 && a>.31 && a<.7)group=7;
   else if(a>.78)group=0;
   else if(a>.59)group=6;
   else if(a>.39)group=4;
   else if(a>.26)group=2;
   else if(a>.115)group=5;
   else group=((Math.sin(theta*8+t)>0 && r>.69)?3:1);
   const dither=((x&1)*2+(y&1))*0.17-0.21;
   pixels[y*w+x]=(group<<5)+Math.max(0,Math.min(31,Math.round(intensity*31+dither)));
  }
 }
 return pixels;
}
function main(){
 const mode=process.argv[2]||'--write',directory=path.resolve(__dirname,'..','assets/profile-banners/premium-lab');
 if(!['--write','--check'].includes(mode))throw new Error('Usage: node scripts/render-cinematic-plasma.cjs --write|--check');
 const n=20,delay=11;let failed=false;
 for(const [surface,[w,h]] of Object.entries(surfaces)){
  const frames=[];for(let i=0;i<n;i++)frames.push(render(w,h,i/n));
  const binary=writeGIF(w,h,frames,delay);const target=path.join(directory,'01-aether-plasma-iris-'+surface+'.gif');
  if(mode==='--write'){fs.mkdirSync(directory,{recursive:true});fs.writeFileSync(target,binary);}else if(!fs.existsSync(target)||!fs.readFileSync(target).equals(binary)){console.error('Mismatch',target);failed=true;}
  console.log(surface,w,h,'frames',n,'bytes',binary.length,'motion=full-field-pixel-shape-evolution');
 }
 if(failed)process.exitCode=1;
}
if(require.main===module)main();
module.exports={render,writeGIF,surfaces,palette};
