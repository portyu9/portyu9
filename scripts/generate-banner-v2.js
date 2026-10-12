'use strict';
/* Deterministic, dependency-free cinematic banner generator. Use --write to create V2 assets, --check to verify. */
const fs = require('node:fs'), path=require('node:path');
const SCENES=[
  [
    "01-orbital-relay",
    "Orbital Relay",
    "Interlocked plasma orbits, communication apertures and beam relays"
  ],
  [
    "02-prism-vault",
    "Prism Vault",
    "Luminous crystalline vault, volumetric facets and optical tunnel"
  ],
  [
    "03-neural-weave",
    "Neural Weave",
    "Dense neural synapses and streaming connection webs"
  ],
  [
    "04-spectral-tides",
    "Spectral Tides",
    "Flowing plasma interference currents and brilliant wave ribbons"
  ],
  [
    "05-fractal-iris",
    "Fractal Iris",
    "A brilliant electric-pink plasma corona around a black void, with hundreds of cyan filaments"
  ],
  [
    "06-circuit-basilica",
    "Circuit Basilica",
    "Architectural photon vault and symmetrical high-energy circuitry"
  ],
  [
    "07-singularity-mesh",
    "Singularity Mesh",
    "Gravitational space-time warp, caustic event horizon and accretion streams"
  ]
];
function rng(seed){let x=seed>>>0;return function(){x^=x<<13;x^=x>>>17;x^=x<<5;return (x>>>0)/4294967296}}
function svgScene(slug,mode){
const idx=SCENES.findIndex(s=>s[0]===slug), title=SCENES[idx][1],description=SCENES[idx][2],W=mode==="compact"?640:1280,H=mode==="compact"?196:mode==="bottom"?150:258,tail=mode==="bottom",compact=mode==="compact",density=tail?.59:compact?.77:1,scale=(n)=>Number(n.toFixed(1)),PI=Math.PI,cx=W/2,cy=H/2;
const random=rng(9001+idx*3989+(tail?57:compact?31:0)),rr=(a,b)=>a+(b-a)*random(),pick=(a)=>a[Math.floor(random()*a.length)];
const cyan="#36DEFF",blue="#377CFF",magenta="#FF37CE",pink="#FF81ED",mint="#39FFD9",violet="#9656FF",white="#E5F8FF";
const colors=[cyan,cyan,magenta,pink,cyan,mint,blue,magenta];
let art=[],glow=[],motion=[],back=[];
const p=(x,y)=>`${scale(x)} ${scale(y)}`,v=(x,y)=>`${scale(x)},${scale(y)}`,path=(d,col,width=1,op=.8,bright=false)=>{const s=`<path d="${d}" fill="none" stroke="${col}" stroke-width="${scale(width)}" opacity="${scale(op)}" stroke-linecap="round" stroke-linejoin="round"/>`;art.push(s);if(bright)glow.push(`<path d="${d}" fill="none" stroke="${col}" stroke-width="${scale(width*2.9+1)}" opacity="${scale(op*.44)}" stroke-linecap="round"/>`)};
const ellipse=(x,y,rx,ry,stroke,sw=1,opacity=.7)=>art.push(`<ellipse cx="${scale(x)}" cy="${scale(y)}" rx="${scale(rx)}" ry="${scale(ry)}" fill="none" stroke="${stroke}" stroke-width="${sw}" opacity="${scale(opacity)}"/>`);
const fillEllipse=(x,y,rx,ry,fill,opacity=1)=>art.push(`<ellipse cx="${scale(x)}" cy="${scale(y)}" rx="${scale(rx)}" ry="${scale(ry)}" fill="${fill}" opacity="${opacity}"/>`);
const poly=(coords,fill,stroke,sw=1,opacity=.5)=>art.push(`<polygon points="${coords.map(q=>v(q[0],q[1])).join(" ")}" fill="${fill}" stroke="${stroke}" stroke-width="${sw}" opacity="${scale(opacity)}"/>`);
const sparks=(count)=>{for(let i=0;i<count;i++){let x=rr(0,W),y=rr(0,H),r=rr(.28,1.7);let col=pick([cyan,magenta,mint,blue]);back.push(`<circle cx="${scale(x)}" cy="${scale(y)}" r="${scale(r)}" fill="${col}" opacity="${scale(rr(.24,.87))}"/>`)}};
sparks(Math.ceil(115*density));
const hor=(count,amp)=>{for(let i=0;i<count;i++){let y=H*(.08+i/(count-1)*.84),offset=rr(-20,20);let d=`M ${p(-15,y+offset)} C ${p(W*.19,y-amp)} ${p(W*.32,y+amp)} ${p(W*.5,y+offset)} S ${p(W*.83,y-amp)} ${p(W+15,y+offset)}`;path(d,i%4===0?magenta:cyan,rr(.34,.8),rr(.075,.27),false)}};
if(idx===0){
  // Three large, connected orbiter spheres, wrapped in multi-axis luminous plasma.
  const orbitalCenters=[W*.19,W*.5,W*.81];let orbRy=H*.50;
  for(let j=0;j<3;j++){let ox=orbitalCenters[j],radiusW=W*(j===1?.238:.194);
    back.push(`<ellipse cx="${scale(ox)}" cy="${scale(cy)}" rx="${scale(radiusW*.9)}" ry="${scale(orbRy*.86)}" fill="url(#aura)" opacity=".55"/>`);
    for(let k=0;k<Math.ceil(31*density);k++){const a=(k/31)*PI*.92+rr(-.04,.04),s=rr(-1,1), rx=radiusW*(.43+.48*k/31),ry=orbRy*(.32+.62*k/31), x0=ox-rx,y0=cy+s*14, x1=ox+rx,y1=cy-s*14;path(`M ${p(x0,y0)} C ${p(ox-rx*.22,cy-ry)} ${p(ox+rx*.28,cy+ry)} ${p(x1,y1)}`,k%6===0?pink:k%3===0?mint:cyan,rr(.6,1.4),rr(.18,.83),k%13===0)}
    for(let r=0;r<10;r++){ellipse(ox,cy,radiusW*(.18+r*.08),orbRy*(.15+r*.09),r%3===0?magenta:cyan,rr(.55,1.3),rr(.28,.72))}
    fillEllipse(ox,cy,radiusW*.16,H*.105,"url(#core)");
    ellipse(ox,cy,radiusW*.16,H*.105,pink,2,.9);
  }
  for(let i=0;i<Math.ceil(170*density);i++){let x=rr(0,W),y=rr(0,H),target=i%2===0?W*.5:i%4===1?W*.19:W*.81;path(`M ${p(x,y)} Q ${p((x+target)*.5,cy+rr(-H*.46,H*.46))} ${p(target,cy+rr(-H*.14,H*.14))}`,pick(colors),rr(.32,1.15),rr(.10,.48),i%31===0)}
  hor(28,18);
}else if(idx===1){
  // A cathedral of refractive vault polygons, splintered by long optical facets.
  let layers=Math.ceil(47*density);
  for(let k=0;k<layers;k++){let f=k/(layers-1), hw=W*(.08+.47*f),hh=H*(.15+.53*f), ridge=H*(.09-.13*f);
     let pts=[[cx-hw,cy+hh*.72],[cx-hw*.85,cy-hh*.52],[cx,cy-hh-ridge],[cx+hw*.85,cy-hh*.52],[cx+hw,cy+hh*.72],[cx,cy+hh*.16]];
     poly(pts,k%5===0?"url(#facet)":"none",k%4===0?magenta:cyan,k%6===0?1.4:.68,.18+.65*(1-f));
  }
  for(let k=0;k<Math.ceil(205*density);k++){let left=k%2===0,shift=rr(0,W*.51),sy=rr(-H*.4,H*1.4),centerX=cx+rr(-W*.11,W*.11),centerY=cy+rr(-H*.25,H*.3);path(`M ${p(left?-15:W+15,sy)} L ${p(cx+(left?-1:1)*shift*.6,rr(0,H))} L ${p(centerX,centerY)}`,pick(colors),rr(.4,1.35),rr(.11,.71),k%25===0)}
  back.push(`<ellipse cx="${cx}" cy="${cy}" rx="${scale(W*.18)}" ry="${scale(H*.54)}" fill="url(#aura)" opacity=".55"/>`);
  fillEllipse(cx,cy,W*.073,H*.285,"url(#core)");ellipse(cx,cy,W*.074,H*.287,pink,3,.95);
}else if(idx===2){
  // Dense flowing synaptic ribbons with luminous pinpoints, connecting two neural vortices.
  let centers=[{x:W*.30,y:H*.5},{x:W*.70,y:H*.5}];
  for(let i=0;i<Math.ceil(265*density);i++){let from=centers[i%2],to=centers[(i+1)%2],d=rr(0,2*PI),q=rr(.15,.95), x=from.x+Math.cos(d)*W*.24*q,y=from.y+Math.sin(d)*H*.53*q,endX=to.x+rr(-W*.25,W*.25),endY=cy+rr(-H*.6,H*.6);path(`M ${p(x,y)} C ${p(x+rr(-W*.11,W*.11),y+rr(-H*.38,H*.38))} ${p(endX+rr(-W*.12,W*.12),endY+rr(-H*.29,H*.29))} ${p(endX,endY)}`,i%9===0?pink:i%3===0?magenta:cyan,rr(.4,1.55),rr(.24,.81),i%21===0);
   if(i%2===0){let rad=rr(.7,2.6);art.push(`<circle cx="${scale(endX)}" cy="${scale(endY)}" r="${scale(rad)}" fill="${i%5===0?magenta:cyan}" opacity="${scale(rr(.3,.9))}"/>`)}
  }
  for(let j=0;j<2;j++){let x=centers[j].x;back.push(`<ellipse cx="${scale(x)}" cy="${cy}" rx="${scale(W*.26)}" ry="${scale(H*.62)}" fill="url(#aura)" opacity=".43"/>`);for(let r=0;r<23;r++){let th=(r*2*PI/23),ex=x+Math.cos(th)*W*.065,ey=cy+Math.sin(th)*H*.2;ellipse(ex,ey,W*.015,H*.044,r%2?magenta:mint,1,.44)}fillEllipse(x,cy,W*.028,H*.1,"url(#core)")}
}else if(idx===3){
  // Iridescent interference waves take over the entire frame.
  for(let i=0;i<Math.ceil(275*density);i++){let level=i/275,s=i%2===0?1:-1,mid=cy+rr(-H*.11,H*.11),amp=H*(.12+level*.40),startY=cy+s*H*(level-.36),phase=rr(0,PI*2);
    let d=`M ${p(-20,startY)} C ${p(W*.18,mid+Math.sin(phase)*amp)} ${p(W*.32,mid-s*amp)} ${p(W*.49,mid+Math.sin(phase+1.5)*amp)} S ${p(W*.76,mid+s*amp)} ${p(W+20,cy+s*H*(.48-level))}`;
    path(d,i%7===0?pink:i%4===0?magenta:i%3===0?mint:cyan,rr(.42,1.5),rr(.16,.82),i%17===0);
  }
  for(let i=0;i<35;i++){let x=W*(i+.5)/35;let y=cy+Math.sin(i*.7)*H*.35;path(`M ${p(x,y-H*.4)} Q ${p(x+W*.025,cy)} ${p(x,y+H*.4)}`,magenta,rr(.3,1.2),.33,i%7===0)}
  hor(40,H*.13);
}else if(idx===4){
  // The reference-driven dense filament corona; never a tiny sparse geometric iris.
  const rx=W*(tail?.075:compact?.12:.11),ry=H*(tail?.29:.31);
  let lobes=Math.ceil(34*density);
  for(let l=0;l<lobes;l++){let a=l*2*PI/lobes,tipx=cx+Math.cos(a)*W*.48,tipy=cy+Math.sin(a)*H*.57;
    let pts=[[cx+Math.cos(a-.11)*rx,cy+Math.sin(a-.11)*ry],[cx+Math.cos(a-.18)*W*.33,cy+Math.sin(a-.18)*H*.43],[tipx,tipy],[cx+Math.cos(a+.18)*W*.33,cy+Math.sin(a+.18)*H*.43],[cx+Math.cos(a+.11)*rx,cy+Math.sin(a+.11)*ry]];
    poly(pts,l%4===0?"#480025":"#130022",l%3===0?magenta:blue,.8,.22);
  }
  back.push(`<ellipse cx="${cx}" cy="${cy}" rx="${scale(W*.21)}" ry="${scale(H*.59)}" fill="url(#pinkGlow)" opacity=".92"/>`);
  let count=Math.ceil(475*density); for(let i=0;i<count;i++){let a=2*PI*i/count+rr(-.024,.024),j=rr(-.16,.16),f=rr(.72,1.19),u=Math.cos(a),vv=Math.sin(a);
    let x0=cx+rx*u,y0=cy+ry*vv;
    let x1=cx+W*.165*Math.cos(a+j),y1=cy+H*.39*Math.sin(a+j*2);
    let x2=cx+W*.36*f*Math.cos(a+j*.45),y2=cy+H*.53*f*Math.sin(a+j*.45);
    let x3=cx+W*.54*f*Math.cos(a+j*.78),y3=cy+H*.73*f*Math.sin(a+j*.78);
    const col=i%8===0?white:i%5===0?pink:i%4===0?magenta:i%3===0?blue:cyan;
    path(`M ${p(x0,y0)} C ${p(x1,y1)} ${p(x2,y2)} ${p(x3,y3)}`,col,rr(.45,1.55),rr(.26,.96),i%19===0);
  }
  art.push(`<ellipse cx="${cx}" cy="${cy}" rx="${scale(rx*1.21)}" ry="${scale(ry*1.25)}" fill="url(#pinkGlow)" opacity=".69"/>`);
  art.push(`<ellipse cx="${cx}" cy="${cy}" rx="${scale(rx)}" ry="${scale(ry)}" fill="#04030a" stroke="${magenta}" stroke-width="${scale(Math.max(2,H*.016))}"/>`);
  ellipse(cx,cy,rx*1.09,ry*1.13,pink,1.3,.9);
}else if(idx===5){
  // Architectural megalith, raised flying buttresses, and high-voltage branching circuits.
  for(let i=0;i<Math.ceil(190*density);i++){let side=i%2===0?-1:1,s=rr(0,1),startX=cx+side*W*(.05+.49*s),endX=cx+side*W*(.045+.11*rr(0,1)),startY=rr(-H*.2,H*1.3),endY=cy+rr(-H*.23,H*.25),midX=cx+side*W*(.09+.21*s);
    path(`M ${p(startX,startY)} L ${p(midX,startY)} Q ${p(midX,cy+(startY-cy)*.3)} ${p(midX,endY)} L ${p(endX,endY)}`,i%6===0?pink:i%4===0?mint:cyan,rr(.52,1.35),rr(.23,.82),i%17===0);
  }
  let arches=Math.ceil(48*density);
  for(let k=0;k<arches;k++){let f=k/arches,span=W*(.06+.42*f),height=H*(.12+.8*f),rise=H*.14*(1-f);
    let d=`M ${p(cx-span,H+9)} L ${p(cx-span,cy-rise)} Q ${p(cx,cy-height)} ${p(cx+span,cy-rise)} L ${p(cx+span,H+9)}`;
    path(d,k%5===0?pink:k%4===0?mint:cyan,k%7===0?1.7:.8,.25+.55*(1-f),k%9===0);
  }
  for(let k=0;k<Math.ceil(62*density);k++){let u=(k+.5)/62, side=k%2?-1:1,dx=side*W*.48*u;path(`M ${p(cx+dx,-H*.15)} L ${p(cx+dx*.77,H*.26)} L ${p(cx+dx*.64,H*.95)}`,k%4===0?magenta:blue,.7,.27,k%11===0)}
  art.push(`<path d="M ${p(cx-W*.12,H*.78)} L ${p(cx-W*.12,H*.31)} L ${p(cx,H*.025)} L ${p(cx+W*.12,H*.31)} L ${p(cx+W*.12,H*.78)} Z" fill="url(#facet)" stroke="${pink}" stroke-width="2" opacity=".82"/>`);
  fillEllipse(cx,cy,W*.033,H*.12,"url(#core)");
}else{
  // Spacetime caustics: warped horizon lines plus luminous disk and twin jets.
  let count=Math.ceil(245*density);
  for(let i=0;i<count;i++){let y=rr(-H*.29,H*1.29),amplitude=rr(H*.10,H*.76),side=i%2===0?1:-1,dist=rr(.07,.85),col=i%8===0?pink:i%5===0?mint:i%3===0?magenta:cyan;
    path(`M ${p(-20,y)} C ${p(W*.22,y+side*amplitude)} ${p(W*.37,cy+side*H*.43*dist)} ${p(cx,cy+side*H*.4*dist)} S ${p(W*.8,y-side*amplitude)} ${p(W+20,y)}`,col,rr(.42,1.45),rr(.16,.67),i%23===0);
  }
  for(let i=0;i<Math.ceil(68*density);i++){let f=i/68,rx=W*(.085+f*.405),ry=H*(.29+f*.45);ellipse(cx,cy,rx,ry,i%7===0?pink:i%3===0?magenta:blue,i%12===0?1.6:.55,.13+.57*(1-f))}
  for(let i=0;i<Math.ceil(90*density);i++){let sign=i%2?1:-1,s=rr(.06,.9),x=cx+sign*W*.11,y=cy+rr(-H*.16,H*.16);path(`M ${p(x,y)} Q ${p(cx+sign*W*(.17+s*.2),cy+rr(-H*.6,H*.6))} ${p(cx+sign*W*.54,cy+rr(-H*.56,H*.56))}`,i%6===0?pink:cyan,rr(.5,1.3),rr(.18,.68),i%17===0)}
  back.push(`<ellipse cx="${cx}" cy="${cy}" rx="${scale(W*.2)}" ry="${scale(H*.57)}" fill="url(#aura)" opacity=".76"/>`);
  fillEllipse(cx,cy,W*.095,H*.28,"#03020a");
  ellipse(cx,cy,W*.099,H*.3,pink,2.5,.9);
  ellipse(cx,cy,W*.118,H*.35,cyan,1.3,.82);
}
let backdrop=`<rect width="${W}" height="${H}" fill="#03050b"/><rect width="${W}" height="${H}" fill="url(#night)"/><rect width="${W}" height="${H}" fill="url(#edge)" opacity=".67"/>`;
const defs=`<defs><radialGradient id="night"><stop stop-color="#140324" stop-opacity=".85"/><stop offset=".57" stop-color="#07091a" stop-opacity=".83"/><stop offset="1" stop-color="#020408"/></radialGradient><radialGradient id="edge"><stop offset=".42" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".85"/></radialGradient><radialGradient id="core"><stop stop-color="#020610"/><stop offset=".73" stop-color="#06132a"/><stop offset="1" stop-color="#26dcff"/></radialGradient><radialGradient id="aura"><stop stop-color="#FF35CD" stop-opacity=".63"/><stop offset=".3" stop-color="#563fe4" stop-opacity=".31"/><stop offset="1" stop-color="#03050b" stop-opacity="0"/></radialGradient><radialGradient id="pinkGlow"><stop stop-color="#FF3EC8" stop-opacity=".22"/><stop offset=".64" stop-color="#FC229F" stop-opacity=".73"/><stop offset="1" stop-color="#FD34CA" stop-opacity="0"/></radialGradient><linearGradient id="facet" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#0b1440" stop-opacity=".05"/><stop offset=".49" stop-color="#FA2FD8" stop-opacity=".25"/><stop offset="1" stop-color="#23D6FF" stop-opacity=".07"/></linearGradient><filter id="softGlow" x="-25%" y="-100%" width="150%" height="300%" color-interpolation-filters="sRGB"><feGaussianBlur stdDeviation="${tail?2.0:2.8}"/></filter></defs>`;
const timer=`<g class="motion" opacity=".33"><path d="M ${p(0,H*.14)} Q ${p(W*.52,H*.42)} ${p(W,H*.14)}" fill="none" stroke="${magenta}" stroke-width="2" stroke-dasharray="3 32"><animate attributeName="stroke-dashoffset" values="0;-210" dur="17s" repeatCount="indefinite"/></path><path d="M ${p(0,H*.85)} Q ${p(W*.48,H*.57)} ${p(W,H*.85)}" fill="none" stroke="${cyan}" stroke-width="2" stroke-dasharray="2 29"><animate attributeName="stroke-dashoffset" values="0;220" dur="13s" repeatCount="indefinite"/></path></g>`;
const style=`<style>.motion{opacity:.33}@media(prefers-reduced-motion:reduce){.motion{display:none}}</style>`;
const safeSlug=slug.replace(/[^a-z0-9-]/g,"");
return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="${W*3}" height="${H*3}" viewBox="0 0 ${W} ${H}" fill="none" shape-rendering="geometricPrecision" data-banner-art="premium-collection-v2" data-scene="${safeSlug}" data-surface="${mode}"><title id="title">${title} — ${mode==="top"?"cinematic desktop crown":mode==="compact"?"responsive compact crown":"kinetic closing horizon"}</title><desc id="desc">${description}. Self-contained vivid plasma artwork; reduced-motion media query disables motion overlay.</desc>${defs}${style}${backdrop}<g>${back.join("")}</g><g>${glow.join("")}</g><g filter="url(#softGlow)">${glow.join("")}</g><g>${art.join("")}</g>${timer}</svg>\n`;
}
const root=path.resolve(__dirname,'..'),outdir=path.join(root,'assets/profile-banners/daily-v2');
if(!process.argv.includes('--write')&&!process.argv.includes('--check')){console.error('Usage: node scripts/generate-banner-v2.js --write|--check');process.exit(2)}
let ok=true;for(const [slug] of SCENES){for(const [variant,suffix] of [['top','top'],['compact','top-compact'],['bottom','bottom']]){const output=svgScene(slug,variant),filename=path.join(outdir,slug+'-'+suffix+'.svg');if(process.argv.includes('--write')){fs.mkdirSync(outdir,{recursive:true});fs.writeFileSync(filename,output)}else{if(!fs.existsSync(filename)||fs.readFileSync(filename,'utf8')!==output){console.error('MISMATCH '+filename);ok=false}}}}
if(!ok)process.exit(1);console.log('Banner V2: '+SCENES.length*3+' deterministic SVGs '+(process.argv.includes('--write')?'generated':'verified'));
