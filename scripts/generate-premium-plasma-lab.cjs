#!/usr/bin/env node
/* Review-only deterministic SVG creator. No production READMEs, publisher or rotation changes. */
"use strict";
const fs=require("node:fs"),path=require("node:path");
function seeded(seed){let s=seed>>>0;return function(){s^=s<<13;s^=s>>>17;s^=s<<5;return (s>>>0)/4294967296;}}
function build(surface){
 const W=surface==="top-compact"?640:1280,H=surface==="bottom"?150:surface==="top-compact"?196:258;
 const isMobile=surface==="top-compact",isBottom=surface==="bottom";
 const r=seeded(0xA3FC41+(surface==="top"?1:surface==="top-compact"?2:3));
 const rand=(lo,hi)=>lo+r()*(hi-lo), fmt=n=>Number(n.toFixed(2)), xy=(x,y)=>`${fmt(x)} ${fmt(y)}`, CX=W/2,CY=H*(isBottom?.61:.5);
 const P=Math.PI, colors=["#00E6FF","#3BBFFF","#00FBCC","#E328FC","#FF48C8","#A76FFF","#D8F6FF"];
 const nCorona=isMobile?275:isBottom?240:405;
 const nFlow=isMobile?95:isBottom?95:150;
 const nArcs=isMobile?36:isBottom?33:54;
 const nDust=isMobile?85:isBottom?72:124;
 const iv=isBottom?.76:isMobile?.83:1;
 const rxCore=W*(isMobile?.138:isBottom?.078:.077),ryCore=H*(isBottom?.28:.258);
 const fullRX=W*(isMobile?.70:.59), fullRY=H*(isBottom?1.47:.90);
 let dust=[], backdrop=[], fibers=[],waves=[],rim=[],highlights=[],motion=[],sparks=[],bloom=[];
 const path=(d,col,width,op,cls="")=>`<path d="${d}" fill="none" stroke="${col}" stroke-width="${fmt(width)}" stroke-opacity="${fmt(op)}" stroke-linecap="round"${cls?` class="${cls}"`:""}/>`;
 const ellipse=(x,y,rx,ry,fill,op)=>`<ellipse cx="${fmt(x)}" cy="${fmt(y)}" rx="${fmt(rx)}" ry="${fmt(ry)}" fill="${fill}" opacity="${fmt(op)}"/>`;
 const coords=(rx,ry,a)=>[CX+rx*Math.cos(a),CY+ry*Math.sin(a)];
 const arcPath=(rx,ry,a1,a2)=>{const [x1,y1]=coords(rx,ry,a1),[x2,y2]=coords(rx,ry,a2);return`M ${xy(x1,y1)} A ${fmt(rx)} ${fmt(ry)} 0 ${Math.abs(a2-a1)>P?1:0} 1 ${xy(x2,y2)}`;};
 backdrop.push(ellipse(CX,CY,W*.43,H*.9,"url(#etherBloom)",.71));
 backdrop.push(ellipse(CX-W*.29,CY-H*.01,W*.4,H*.79,"url(#cyanCloud)",.57));
 backdrop.push(ellipse(CX+W*.27,CY+H*.02,W*.39,H*.84,"url(#violetCloud)",.64));
 backdrop.push(ellipse(CX,CY,W*.2,H*.66,"url(#roseCloud)",.85));
 // Undulating 3-D caustic ribbons across the entire aspect ratio.
 for(let i=0;i<nFlow;i++){
    const t=(i+.5)/nFlow,side=i%2?1:-1,sideBias=(t-.5)*H*.72;
    const y0=CY+sideBias+rand(-H*.13,H*.13), y1=CY+sideBias*.36+rand(-H*.3,H*.3);
    const x0=side>0?W+14:-14, x1=CX+side*rxCore*rand(1.16,1.85);
    const bend=side*W*rand(.15,.35);
    const c1x=CX+side*W*.39,c2x=CX+side*W*rand(.19,.34);
    const c1y=y0+rand(-H*.5,H*.5), c2y=y1+rand(-H*.41,H*.41);
    const d=`M ${xy(x0,y0)} C ${xy(c1x,c1y)} ${xy(c2x,c2y)} ${xy(x1,y1)}`;
    const col=i%10===0?"#E328FC":i%7===0?"#00FBCC":i%3===0?"#FF48C8":"#00E6FF";
    const opacity=rand(.13,.56);
    waves.push(path(d,col,rand(.48,1.26),opacity));
    if(i%17===0)bloom.push(path(d,col,2.9,opacity*.4));
 }
 // Hundreds of intrinsically curving plasma streamlines spiral out from the eye.
 for(let i=0;i<nCorona;i++){
   const a=(i+.5)*(2*P/nCorona)+rand(-.02,.02);
   const endR=rand(.61,1.08),endRX=fullRX*endR,endRY=fullRY*endR;
   const [sx,sy]=coords(rxCore*rand(1.05,1.18),ryCore*rand(1.1,1.25),a+rand(-.045,.045));
   const [ex,ey]=coords(endRX,endRY,a+rand(-.17,.17));
   const tangent=rand(-1,1)*H*.42+Math.sin(a*7.2)*H*.17;
   const m1x=sx+(ex-sx)*rand(.18,.36)+-Math.sin(a)*tangent*.65,m1y=sy+(ey-sy)*rand(.28,.42)+Math.cos(a)*tangent*.7;
   const m2x=sx+(ex-sx)*rand(.65,.84)+Math.sin(a)*tangent*.47,m2y=sy+(ey-sy)*rand(.66,.85)-Math.cos(a)*tangent*.69;
   const d=`M ${xy(sx,sy)} C ${xy(m1x,m1y)} ${xy(m2x,m2y)} ${xy(ex,ey)}`;
   const col=i%17===0?"#E9FAFF":i%9===0?"#FF48C8":i%7===0?"#00FBCC":(i%4===0?"#E328FC":"#00E6FF");
   const opacity=rand(.2,.81),sw=rand(.34,1.22)*iv;
   fibers.push(path(d,col,sw,opacity));
   if(i%19===0) bloom.push(path(d,col,sw*3.8,opacity*.55));
   if(i%7===0){
       const start=rand(0,155),duration=fmt(rand(4.7,12.5));
       motion.push(`<path d="${d}" fill="none" stroke="${col}" stroke-width="${fmt(rand(1.2,2.6))}" stroke-linecap="round" stroke-dasharray="${fmt(rand(4,15))} ${fmt(rand(115,195))}" opacity="${fmt(rand(.35,.78))}"><animate attributeName="stroke-dashoffset" values="0;-260" dur="${duration}s" begin="-${fmt(start)}s" repeatCount="indefinite"/></path>`);
   }
 }
 // Disciplined concentric plasma arcs: not polygonal outlines.
 for(let i=0;i<nArcs;i++){
    const t=i/(nArcs-1),rx=rxCore*(1.18+t*2.15),ry=ryCore*(1.15+t*1.07);
    const a1=rand(-P,P),len=rand(.27,1.83),a2=a1+len;
    const col=i%6===0?"#F6DFFF":i%3===0?"#FF48C8":"#00E6FF";
    const d=arcPath(rx,ry,a1,a2);
    rim.push(path(d,col,rand(.6,2),rand(.18,.69)));
    if(i%9===0)bloom.push(path(d,col,rand(2.1,3.2),.47));
 }
 // Optical streamers crossing the upper and lower landscape.
 for(let k=0;k<(isMobile?50:isBottom?54:82);k++){
    const t=k/(isMobile?50:isBottom?54:82),side=k%2?1:-1,s=rand(.25,1.0);
    const ox=CX+side*W*(.14+t*.55),oy=CY+rand(-H*.55,H*.55);
    const ex=CX+side*W*rand(.20,.57),ey=CY+side*H*(t-.5)+rand(-H*.27,H*.27);
    const col=k%8===0?"#E328FC":k%4===0?"#00FBCC":"#309FFF";
    highlights.push(path(`M ${xy(ox,oy)} Q ${xy(CX+side*W*.28, CY+rand(-H*.75,H*.75))} ${xy(ex,ey)}`,col,rand(.35,1.1),rand(.09,.3)));
 }
 // Floating luminous dust anchored throughout the full landscape.
 for(let i=0;i<nDust;i++){
    let x=rand(5,W-5),y=rand(6,H-6);
    let rad=rand(.18,1.45),op=rand(.21,.79);
    const col=colors[Math.floor(r()*colors.length)];
    if(i%11===0){sparks.push(`<circle cx="${fmt(x)}" cy="${fmt(y)}" r="${fmt(rad*1.5)}" fill="${col}" opacity=".12"><animate attributeName="opacity" values=".08;.68;.08" dur="${fmt(rand(3.4,7.3))}s" begin="-${fmt(rand(0,7))}s" repeatCount="indefinite"/></circle>`);}
    dust.push(`<circle cx="${fmt(x)}" cy="${fmt(y)}" r="${fmt(rad)}" fill="${col}" opacity="${fmt(op)}"/>`);
 }
 // Halo-rim layers and a convincing deep-black center.
 const core=[
   ellipse(CX,CY,rxCore*2.2,ryCore*2.18,"url(#roseCloud)",.78),
   ellipse(CX,CY,rxCore*1.56,ryCore*1.64,"url(#irisHalo)",.86),
   ellipse(CX,CY,rxCore*1.21,ryCore*1.27,"url(#cyanCloud)",.60),
   ellipse(CX,CY,rxCore,ryCore,"#02030B",1),
   `<ellipse cx="${fmt(CX)}" cy="${fmt(CY)}" rx="${fmt(rxCore*1.05)}" ry="${fmt(ryCore*1.055)}" fill="none" stroke="url(#spectralStroke)" stroke-width="${fmt(Math.max(2,H*.014))}" opacity=".90"/>`,
   `<ellipse cx="${fmt(CX)}" cy="${fmt(CY)}" rx="${fmt(rxCore*1.125)}" ry="${fmt(ryCore*1.14)}" fill="none" stroke="#FF4DBB" stroke-opacity=".55" stroke-width="1.55"/>`,
   `<ellipse cx="${fmt(CX)}" cy="${fmt(CY)}" rx="${fmt(rxCore*.86)}" ry="${fmt(ryCore*.86)}" fill="none" stroke="#392245" stroke-opacity=".6" stroke-width="1"/>`,
   ellipse(CX-rxCore*.26,CY-ryCore*.21,rxCore*.61,ryCore*.52,"url(#shadowCore)",.7)
 ];
 // Aligned animated arcs: layered subtle orbital phase, not full image rotation.
 let orbit=[];
 for(let i=0;i<17;i++){
   const a=2*P*i/17,rx=rxCore*rand(1.44,2.18),ry=ryCore*rand(1.42,2.07),len=rand(.14,.39);
   const d=arcPath(rx,ry,a,a+len),col=i%3===0?"#00FBCC":i%2===0?"#FF48C8":"#D9FFFF";
   orbit.push(path(d,col,rand(1.1,2.2),rand(.34,.74)));
 }
 let movingRings=`<g class="motion-rotor"><g>${orbit.join("")}<animateTransform attributeName="transform" type="rotate" values="-8 ${fmt(CX)} ${fmt(CY)};8 ${fmt(CX)} ${fmt(CY)};-8 ${fmt(CX)} ${fmt(CY)}" dur="26s" repeatCount="indefinite"/></g></g>`;
 // East/west flares make the edge of the banner compositionally active.
 let tips=[];
 for(let side of [-1,1]){
  let x=CX+side*W*(isMobile?.38:.36),y=CY+rand(-H*.13,H*.13);
  tips.push(ellipse(x,y,W*.16,H*.48,side===1?"url(#violetCloud)":"url(#cyanCloud)",.58));
  tips.push(`<path d="M ${xy(x-side*W*.08,y)} L ${xy(x+side*W*.09,y)} M ${xy(x,y-H*.31)} L ${xy(x,y+H*.31)}" stroke="${side===1?"#E328FC":"#00E6FF"}" stroke-opacity=".34" stroke-width=".85"/>`);
 }
 const defs=`<defs>
 <radialGradient id="etherBloom"><stop stop-color="#E328FC" stop-opacity=".48"/><stop offset=".31" stop-color="#5633BE" stop-opacity=".31"/><stop offset=".7" stop-color="#001A43" stop-opacity=".17"/><stop offset="1" stop-color="#060713" stop-opacity="0"/></radialGradient>
 <radialGradient id="cyanCloud"><stop stop-color="#00E6FF" stop-opacity=".28"/><stop offset=".46" stop-color="#1670FF" stop-opacity=".18"/><stop offset="1" stop-color="#00E6FF" stop-opacity="0"/></radialGradient>
 <radialGradient id="violetCloud"><stop stop-color="#E328FC" stop-opacity=".31"/><stop offset=".43" stop-color="#6548DA" stop-opacity=".17"/><stop offset="1" stop-color="#E328FC" stop-opacity="0"/></radialGradient>
 <radialGradient id="roseCloud"><stop stop-color="#F92BBD" stop-opacity=".49"/><stop offset=".38" stop-color="#A9187C" stop-opacity=".33"/><stop offset="1" stop-color="#F92BBD" stop-opacity="0"/></radialGradient>
 <radialGradient id="irisHalo"><stop stop-color="#050313" stop-opacity="0"/><stop offset=".43" stop-color="#7C0E4F" stop-opacity=".25"/><stop offset=".70" stop-color="#FC38BF" stop-opacity=".75"/><stop offset="1" stop-color="#FD3BD4" stop-opacity="0"/></radialGradient>
 <radialGradient id="shadowCore"><stop stop-color="#000105"/><stop offset=".7" stop-color="#080719"/><stop offset="1" stop-color="#111027" stop-opacity="0"/></radialGradient>
 <linearGradient id="spectralStroke" x1="0" y1="0" x2="${W}" y2="${H}" gradientUnits="userSpaceOnUse"><stop stop-color="#00E6FF"/><stop offset=".25" stop-color="#00FBCC"/><stop offset=".47" stop-color="#FF69D9"/><stop offset=".64" stop-color="#E328FC"/><stop offset="1" stop-color="#00E6FF"/></linearGradient>
 <radialGradient id="bg"><stop stop-color="#0D0920"/><stop offset=".52" stop-color="#040714"/><stop offset="1" stop-color="#02040A"/></radialGradient>
 <filter id="bloom" x="-30%" y="-80%" width="160%" height="260%" color-interpolation-filters="sRGB"><feGaussianBlur stdDeviation="${fmt(isMobile?3.6:isBottom?3.9:5.2)}"/></filter>
 <filter id="coreBloom" x="-65%" y="-100%" width="230%" height="300%" color-interpolation-filters="sRGB"><feGaussianBlur stdDeviation="${fmt(isMobile?5:isBottom?4.7:7)}"/></filter>
 <style>.trail-motion{opacity:.72}.motion-rotor{opacity:.88}.ambient-drift{transform-origin:${fmt(CX)}px ${fmt(CY)}px}@media(prefers-reduced-motion:reduce){.trail-motion{display:none}.motion-rotor animateTransform{display:none}.spark-motion{display:none}.ambient-drift{animation:none}}</style>
</defs>`;
 const source=`<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="${W*3}" height="${H*3}" viewBox="0 0 ${W} ${H}" fill="none" shape-rendering="geometricPrecision" data-banner-art="premium-plasma-lab-v1" data-scene="01-aether-plasma-iris" data-surface="${surface}">
 <title id="title">Aether Flux — Living Plasma Iris (${surface})</title>
 <desc id="desc">An intricate animated field of cyan, teal, and fuchsia plasma filaments converging around a luminous dark iris. Flowing energy trails, pulsating dust, optical turbulence, and a coordinated spatial horizon. Reduced-motion fallback preserves all static artwork.</desc>
 ${defs}
 <rect width="${W}" height="${H}" fill="#02040A"/>
 <rect width="${W}" height="${H}" fill="url(#bg)"/>
 <g>${backdrop.join("")}</g>
 <g>${tips.join("")}</g>
 <g>${highlights.join("")}</g>
 <g>${waves.join("")}</g>
 <g filter="url(#bloom)" opacity=".52">${bloom.join("")}</g>
 <g>${fibers.join("")}</g>
 <g>${rim.join("")}</g>
 <g>${dust.join("")}</g>
 <g class="trail-motion">${motion.join("")}</g>
 <g>${core.join("")}</g>
 <g filter="url(#coreBloom)" opacity=".32"><ellipse cx="${fmt(CX)}" cy="${fmt(CY)}" rx="${fmt(rxCore*1.17)}" ry="${fmt(ryCore*1.24)}" fill="none" stroke="#FD43D4" stroke-width="4.2"/></g>
 ${movingRings}
 <g class="spark-motion">${sparks.join("")}</g>
 <g opacity=".19"><path d="M0 ${fmt(H*.06)}H${W} M0 ${fmt(H*.94)}H${W}" stroke="url(#spectralStroke)" stroke-width=".75" stroke-dasharray="8 16"/></g>
 </svg>
`;
 return source.trim()+"\n";
}
const surfaces=["top","top-compact","bottom"];
const root=path.resolve(__dirname,"..");
const dir=path.join(root,"assets/profile-banners/premium-lab");
const mode=process.argv[2];
if(!["--write","--check"].includes(mode)){console.error("Usage: node scripts/generate-premium-plasma-lab.cjs --write|--check");process.exitCode=2;}
else{
 let bad=0;
 for(const surface of surfaces){
    const name="01-aether-plasma-iris-"+surface+".svg",body=build(surface),dest=path.join(dir,name);
    if(mode==="--write"){fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(dest,body,"utf8");}
    else if(!fs.existsSync(dest)||fs.readFileSync(dest,"utf8")!==body){console.error("MISMATCH "+name);bad++;}
 }
 if(bad){process.exitCode=1;} else console.log("Premium plasma lab: 3 original SVG assets "+(mode==="--write"?"written":"bitwise-verified"));
}
