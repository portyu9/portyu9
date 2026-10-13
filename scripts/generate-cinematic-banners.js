#!/usr/bin/env node
"use strict";
const makeAssets=function cinematicFactory(){
"use strict";
const names=[["01-orbital-relay","Orbital Relay"],["02-prism-vault","Prism Vault"],["03-neural-weave","Neural Weave"],["04-spectral-tides","Spectral Tides"],["05-fractal-iris","Fractal Iris"],["06-circuit-basilica","Circuit Basilica"],["07-singularity-mesh","Singularity Mesh"]];
const colors=["#00E6FF","#E328FC","#00FBCC","#9173FF"];
const n=x=>+x.toFixed(1),q=(x,y)=>n(x)+","+n(y),rand=seed=>()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296};
const path=(d,c="url(#neon)",w=1,o=.5,attrs="")=>`<path d="${d}" fill="none" stroke="${c}" stroke-width="${w}" opacity="${o}" stroke-linecap="round" ${attrs}/>`;
const oval=(x,y,rx,ry,c="url(#neon)",w=1,o=.6,attrs="")=>`<ellipse cx="${n(x)}" cy="${n(y)}" rx="${n(rx)}" ry="${n(ry)}" fill="none" stroke="${c}" stroke-width="${w}" opacity="${o}" ${attrs}/>`;
const dot=(x,y,r,c,o=.6)=>`<circle cx="${n(x)}" cy="${n(y)}" r="${n(r)}" fill="${c}" opacity="${o}"/>`;
const poly=(pts,fill,o)=>`<polygon points="${pts.map(p=>q(...p)).join(" ")}" fill="${fill}" opacity="${o}"/>`;
function ribbon(w,y,am,frequency,phase){
  let d="";for(let k=0;k<=12;k++){const t=k/12,x=w*t,z=y+am*(Math.sin(t*Math.PI*frequency+phase)+.25*Math.sin(t*Math.PI*frequency*2.3+phase*1.8));d+=(k?"L":"M")+q(x,z)}return d;
}
function make(i,surface){
 const [slug,title]=names[i],w=surface==="top-compact"?640:1280,h=surface==="bottom"?150:surface==="top-compact"?196:258;
 const x=w*.5,y=h*.5,r=h*.77,R=rand(24161+i*9181+w*23+h*17);
 let art="",moving="",background="";let grid="",stars="";
 for(let k=1;k<22;k++)grid+=`M${n(w*k/22)},0V${h}`;
 for(let k=1;k<8;k++)grid+=`M0,${n(h*k/8)}H${w}`;
 for(let k=0;k<(w===640?40:65);k++){let sx=R()*w,sy=R()*h;stars+=`M${q(sx,sy)}h${n(.4+R()*1.8)}`;}
 background+=`<rect width="${w}" height="${h}" fill="url(#night)"/><rect width="${w}" height="${h}" fill="url(#ambient)" opacity=".25"/>`;
 art+=`<g opacity=".39">${path(grid,"#5685BC",.55,.36)}${path(stars,"#D7FFFF",1,.8)}</g>`;
 art+=path(`M0,${n(h*.065)}H${n(w*.30)} M${n(w*.70)},${n(h*.065)}H${w} M0,${n(h*.93)}H${n(w*.37)} M${n(w*.63)},${n(h*.93)}H${w}`,"url(#neon)",1,.52);
 art+=`<ellipse cx="${n(x)}" cy="${n(y)}" rx="${n(w*.38)}" ry="${n(h*.85)}" fill="url(#ambient)" opacity=".76"/>`;
 if(i===0){
   for(let k=0;k<18;k++)art+=oval(x,y,w*(.12+k*.025),h*(.17+(k%8)*.049),k%4===0?"url(#neon)":colors[k%4],k%4===0?2:.75,.23+(k%5)*.08,`transform="rotate(${k%2?16+k:-18+k} ${n(x)} ${n(y)})"`);
   let d="";for(let k=0;k<76;k++){let a=k*2.399,rr=r*(.75+R()*1.5),xx=x+Math.cos(a)*rr*3,yy=y+Math.sin(a)*rr*.68;d+=`M${q(xx,yy)}Q${q(xx+Math.cos(a+.2)*18,yy+Math.sin(a+.3)*11)} ${q(xx+Math.cos(a+.8)*37,yy+Math.sin(a+.8)*18)}`;}
   art+=path(d,"url(#neon)",.9,.65)+oval(x,y,r*.89,r*.59,"#00FBCC",2.3,.75)+`<circle cx="${n(x)}" cy="${n(y)}" r="${n(r*.4)}" fill="url(#core)"/>`;
   moving+=`<g class="motion">${oval(x,y,r*1.27,r*.38,"url(#neon)",3,.88,'stroke-dasharray="40 47"')}<animateTransform attributeName="transform" type="rotate" values="0 ${n(x)} ${n(y)};360 ${n(x)} ${n(y)}" dur="24s" repeatCount="indefinite"/></g>`;
   moving+=`<path class="motion" d="${ribbon(w,y,h*.14,3.3,.2)}" fill="none" stroke="#00FBCC" stroke-dasharray="30 66"><animate attributeName="stroke-dashoffset" values="0;-220" dur="8s" repeatCount="indefinite"/></path>`;
   moving+=`<circle class="motion" cx="${n(x)}" cy="${n(y)}" r="${n(r*.19)}" fill="url(#core)"><animate attributeName="r" values="${n(r*.19)};${n(r*.38)};${n(r*.19)}" dur="8s" repeatCount="indefinite"/></circle>`;
 }else if(i===1){
   const span=Math.min(w*.49,h*2);
   for(let k=0;k<14;k++){let f=1-k*.065,rx=span*f,ry=h*.96*f,a=[[x,y-ry],[x+rx,y],[x,y+ry],[x-rx,y]];
     art+=poly(a,k%2?"url(#glassA)":"url(#glassB)",.06+k*.004)+path(`M${q(x,y-ry)}L${q(x+rx,y)} ${q(x,y+ry)} ${q(x-rx,y)}Z`,k%3===0?"url(#neon)":colors[k%4],k%4===0?1.9:.7,.54-k*.022);}
   for(let k=0;k<50;k++){let side=k%2?-1:1,px=x+side*span*(.19+R()*.84),py=y+(R()-.5)*h*2;
     art+=poly([[px,py],[px+side*(18+R()*85),py+(R()-.5)*h*.38],[px+side*(8+R()*42),py+(15+R()*35)]],k%3===0?"url(#glassA)":"url(#glassB)",.10+R()*.20);}
   art+=`<ellipse cx="${n(x)}" cy="${n(y)}" rx="${n(span*.19)}" ry="${n(h*.28)}" fill="url(#core)"/>`;
   moving+=`<g class="motion">${path(`M${q(x-span*.7,y)}L${q(x,y-h*.61)} ${q(x+span*.7,y)} ${q(x,y+h*.61)}Z`,"#E328FC",2.5,.8,'stroke-dasharray="30 75"')}<animateTransform attributeName="transform" type="rotate" values="-9 ${n(x)} ${n(y)};9 ${n(x)} ${n(y)};-9 ${n(x)} ${n(y)}" dur="12s" repeatCount="indefinite"/></g>`;
   moving+=`<path class="motion" d="${ribbon(w,y,h*.07,4.8,.4)}" fill="none" stroke="#00FBCC" stroke-dasharray="8 34"><animate attributeName="stroke-dashoffset" values="0;-175" dur="7s" repeatCount="indefinite"/></path>`;
   moving+=`<ellipse class="motion" cx="${n(x)}" cy="${n(y)}" rx="${n(span*.14)}" ry="${n(h*.33)}" fill="none" stroke="#00E6FF"><animate attributeName="opacity" values=".09;.8;.09" dur="7s" repeatCount="indefinite"/></ellipse>`;
 }else if(i===2){
   for(let k=0;k<18;k++){const yy=h*(.055+k*.05);art+=path(ribbon(w,yy,h*.09,4.6,k*.55),k%5===0?"url(#neon)":colors[k%4],k%4===0?1.8:1,.44+(k%4)*.09);}
   let net="";for(let k=0;k<82;k++){const sx=R()*w,sy=R()*h,ex=sx+(R()-.5)*w*.13,ey=sy+(R()-.5)*h*.32;net+=`M${q(sx,sy)}Q${q((sx+ex)/2,y+(sy-y)*.53)} ${q(ex,ey)}`;}
   art+=path(net,"#809CFF",.75,.43);
   for(let k=0;k<42;k++)art+=dot(R()*w,R()*h,R()*1.4+.7,colors[k%3],.4+R()*.5);
   art+=oval(x,y,w*.15,h*.38,"url(#neon)",1.8,.55)+dot(x,y,5,"#C9FFFF",.85);
   for(let k=0;k<3;k++)moving+=`<path class="motion" d="${ribbon(w,y+(k-1)*h*.22,h*.12,4,k*.8)}" fill="none" stroke="${colors[k]}" stroke-width="2.1" stroke-dasharray="10 43"><animate attributeName="stroke-dashoffset" values="0;${k%2?180:-180}" dur="${5+k*2}s" repeatCount="indefinite"/></path>`;
 }else if(i===3){
   for(let k=0;k<31;k++){const yy=h*(.065+k*.029);art+=path(ribbon(w,yy,h*(.04+(k%8)*.021),2.4+k*.069,k*.20),k%5===0?"url(#neon)":colors[k%4],k%5===0?2.2:.9,.29+(k%5)*.06);}
   let rain="";for(let k=0;k<64;k++){let sx=R()*w,sy=h*(.19+R()*.63);rain+=`M${q(sx,sy)}l${q(6+R()*12,-4-R()*10)}`;}
   art+=path(rain,"#B8FFFF",.9,.58)+`<rect width="${w}" height="${h}" fill="url(#mist)" opacity=".5"/>`;
   for(let k=0;k<3;k++)moving+=`<path class="motion" d="${ribbon(w,y+(k-1)*h*.22,h*.18,2.9+k*.3,k*.65)}" fill="none" stroke="${colors[k]}" stroke-width="3" stroke-dasharray="41 65"><animate attributeName="stroke-dashoffset" values="0;-${n(w*.7)}" dur="${7+k*2}s" repeatCount="indefinite"/></path>`;
 }else if(i===4){
   let strands=["","","","",""];const outerX=w*(w===640?.58:.48),outerY=h*1.03,inner=h*.2;
   for(let k=0;k<166;k++){
     let a=k*2*Math.PI/166+(R()-.5)*.075,b=a+.33+R()*.59,t=.65+R()*.49;
     const p0=[x+Math.cos(a)*outerX*t,y+Math.sin(a)*outerY*t],p1=[x+Math.cos(a+.11)*outerX*.67,y+Math.sin(a+.11)*outerY*.73],p2=[x+Math.cos(b-.1)*outerX*.15,y+Math.sin(b-.1)*outerY*.19],p3=[x+Math.cos(b)*inner*(.5+R()*.61),y+Math.sin(b)*inner*(.5+R()*.61)];
     strands[k%4]+=`M${q(...p0)}C${q(...p1)} ${q(...p2)} ${q(...p3)}`;
   }
   for(let k=0;k<4;k++)art+=path(strands[k],k===3?"url(#neon)":colors[k],k===3?1.65:k===0?1.3:.9,k===3?.83:.63);
   for(let k=0;k<8;k++)art+=oval(x,y,inner*(1.02+k*.28),inner*(.8+k*.23),k%2?"#E328FC":"#00E6FF",k%2?1.4:.9,.73-k*.058);
   art+=`<ellipse cx="${n(x)}" cy="${n(y)}" rx="${n(inner*.91)}" ry="${n(inner*.88)}" fill="#020410" stroke="#E328FC" stroke-width="2"/>`;
   for(let k=0;k<3;k++)moving+=`<g class="motion">${oval(x,y,inner*(2+k*.52),inner*(1.8+k*.44),colors[k],2,.9,'stroke-dasharray="12 31"')}<animateTransform attributeName="transform" type="rotate" values="0 ${n(x)} ${n(y)};${k%2?180:-180} ${n(x)} ${n(y)}" dur="${18+k*6}s" repeatCount="indefinite"/></g>`;
 }else if(i===5){
   let wires=["","",""];for(let side of [-1,1])for(let k=0;k<23;k++){let yy=h*(.06+k*.038),turn=x+side*w*(.14+R()*.17),xe=x+side*(16+R()*w*.09),ye=y+(yy-y)*(.21+R()*.32);
     wires[k%3]+=`M${q(side<0?0:w,yy)}H${n(turn)}L${q(turn+side*w*.025,yy+(ye-yy)*.57)} ${q(xe,ye)}`;}
   for(let k=0;k<3;k++)art+=path(wires[k],colors[k],k===0?1.65:1.15,.53+k*.07);
   for(let k=0;k<13;k++){const f=k/13,rx=w*(.47-f*.39),ry=h*(.8-f*.66);art+=path(`M${q(x-rx,y-ry)}V${n(y+ry)}H${n(x+rx)}V${n(y-ry)}`,"url(#neon)",1,.24+k*.025);}
   for(let k=0;k<49;k++)art+=dot(R()*w,R()*h,R()*1.6+.5,colors[k%3],.21+R()*.57);
   art+=`<rect x="${n(x-w*.065)}" y="${n(y-h*.25)}" width="${n(w*.13)}" height="${n(h*.5)}" rx="${n(h*.05)}" fill="url(#ambient)" stroke="#00E6FF" stroke-opacity=".81"/>`+path(`M${q(x,y-h*.39)}V${n(y+h*.39)} M${q(x-w*.14,y)}H${n(x+w*.14)}`,"url(#neon)",2.2,.85);
   for(let k=0;k<3;k++)moving+=`<path class="motion" d="${wires[k]}" fill="none" stroke="${colors[k]}" stroke-width="2" stroke-dasharray="11 75"><animate attributeName="stroke-dashoffset" values="0;${k%2?160:-160}" dur="${5+k*2}s" repeatCount="indefinite"/></path>`;
 }else{
   for(let k=0;k<25;k++){let off=(k-12)/12,pts=[];for(let j=0;j<=18;j++){let xx=w*j/18,u=(xx-x)/(w*.5);pts.push([xx,y+off*h*.75+Math.sign(off||1)*h*.14*Math.exp(-u*u*11)/(Math.abs(off)+.43)]);}
     art+=path("M"+pts.map(p=>q(...p)).join("L"),k%4===0?"url(#neon)":colors[k%3],k%5===0?1.3:.75,.33);}
   for(let k=0;k<16;k++){let off=(k-7.5)/7.5,pts=[];for(let j=0;j<=13;j++){let yy=h*j/13,u=(yy-y)/(h*.5);pts.push([x+off*w*.43+Math.sign(off)*w*.045*Math.exp(-u*u*8)/(Math.abs(off)+.51),yy]);}
     art+=path("M"+pts.map(p=>q(...p)).join("L"),"#7589F1",.75,.32);}
   for(let k=0;k<10;k++)art+=oval(x,y,r*(1.51+k*.22),r*(.46+k*.055),k%2?"#E328FC":"#00E6FF",k%3===0?2:.9,.65-k*.044,`transform="rotate(${k%2?13:-13} ${n(x)} ${n(y)})"`);
   for(let k=0;k<58;k++){let a=R()*Math.PI*2,rr=r*(1+R()*2);art+=dot(x+Math.cos(a)*rr*(1.5+R()),y+Math.sin(a)*rr*.55,R()*1.3+.6,colors[k%3],.3+R()*.53);}
   art+=`<circle cx="${n(x)}" cy="${n(y)}" r="${n(r*.68)}" fill="#010410" stroke="#B76CFF" stroke-width="2"/>`+oval(x,y,r*.9,r*.9,"#00E6FF",1.7,.85);
   moving+=`<g class="motion">${oval(x,y,r*2.22,r*.62,"url(#neon)",3,.93,'stroke-dasharray="80 36"')}<animateTransform attributeName="transform" type="rotate" values="0 ${n(x)} ${n(y)};360 ${n(x)} ${n(y)}" dur="24s" repeatCount="indefinite"/></g>`;
   moving+=`<g class="motion">${oval(x,y,r*1.72,r*.87,"#E328FC",2,.89,'stroke-dasharray="15 33"')}<animateTransform attributeName="transform" type="rotate" values="0 ${n(x)} ${n(y)};-360 ${n(x)} ${n(y)}" dur="17s" repeatCount="indefinite"/></g>`;
   moving+=`<circle class="motion" cx="${n(x)}" cy="${n(y)}" r="${n(r*.95)}" fill="none" stroke="#00FBCC"><animate attributeName="opacity" values=".13;.65;.13" dur="8s" repeatCount="indefinite"/></circle>`;
 }
 const defs=`<defs><linearGradient id="night" x2="0" y2="1"><stop stop-color="#0B1632"/><stop offset=".5" stop-color="#030614"/><stop offset="1" stop-color="#08152B"/></linearGradient><linearGradient id="neon"><stop stop-color="#00E6FF"/><stop offset=".24" stop-color="#00FBCC"/><stop offset=".57" stop-color="#E328FC"/><stop offset=".83" stop-color="#9173FF"/><stop offset="1" stop-color="#00E6FF"/></linearGradient><linearGradient id="glassA" x2="1" y2="1"><stop stop-color="#E328FC" stop-opacity=".08"/><stop offset=".51" stop-color="#E328FC" stop-opacity=".79"/><stop offset="1" stop-color="#00E6FF" stop-opacity=".04"/></linearGradient><linearGradient id="glassB" x2="1" y2="1"><stop stop-color="#00E6FF" stop-opacity=".07"/><stop offset=".52" stop-color="#00FBCC" stop-opacity=".81"/><stop offset="1" stop-color="#9173FF" stop-opacity=".06"/></linearGradient><radialGradient id="ambient"><stop stop-color="#E328FC" stop-opacity=".49"/><stop offset=".34" stop-color="#00E6FF" stop-opacity=".24"/><stop offset=".76" stop-color="#9173FF" stop-opacity=".09"/><stop offset="1" stop-color="#00111B" stop-opacity="0"/></radialGradient><radialGradient id="core"><stop stop-color="#DCFFFF"/><stop offset=".19" stop-color="#00FBCC" stop-opacity=".82"/><stop offset=".57" stop-color="#00E6FF" stop-opacity=".36"/><stop offset="1" stop-color="#E328FC" stop-opacity="0"/></radialGradient><linearGradient id="mist" x2="0" y2="1"><stop stop-color="#00E6FF" stop-opacity="0"/><stop offset=".5" stop-color="#E328FC" stop-opacity=".19"/><stop offset="1" stop-color="#00FBCC" stop-opacity="0"/></linearGradient><style>.skeleton{opacity:1}.motion{opacity:.93}@media(prefers-color-scheme:light){.skeleton{opacity:1}}@media(prefers-reduced-motion:reduce){.motion{display:none}.skeleton{opacity:1}}</style></defs>`;
 return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="${w*3}" height="${h*3}" viewBox="0 0 ${w} ${h}" fill="none" data-banner-art="rotating-collection-v1" data-scene="${slug}" data-surface="${surface}"><title id="title">${title} / ${surface==="bottom"?"Evidence Horizon":"Signal Crown"}</title><desc id="desc">Luminous futuristic ${title} vector art with coordinated light motion and static reduced-motion fallback.</desc>${defs}${background}<g class="skeleton">${art}</g>${moving}</svg>\n`;
}
function files(){let o={};for(let i=0;i<7;i++)for(const surface of ["top","top-compact","bottom"])o[`assets/profile-banners/daily/${names[i][0]}-${surface}.svg`]=make(i,surface);return o}
return {files,names};
};
module.exports=makeAssets;
if(require.main===module){
 const fs=require("node:fs"),path=require("node:path"),root=path.resolve(__dirname,"..");
 if(process.argv.length!==3||!["--write","--check"].includes(process.argv[2])){console.error("Use --write or --check");process.exit(2)}
 let bad=0;
 for(const [relative,svg] of Object.entries(makeAssets().files())){
   const size=Buffer.byteLength(svg),count=(svg.match(/<animate(?:Transform|Motion)?/g)||[]).length;
   if(size<2400||size>=30000||count<3||!svg.includes(".motion{display:none}"))throw Error("SVG contract "+relative+" size="+size+" animation="+count);
   const dest=path.join(root,relative);
   if(process.argv[2]==="--write"){fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,svg);}
   else if(!fs.existsSync(dest)||fs.readFileSync(dest,"utf8")!==svg){console.error("Out of sync "+relative);bad++;}
   else console.log("OK "+relative+" "+size+" bytes");
 }
 if(bad)process.exit(1);
}
