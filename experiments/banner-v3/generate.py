#!/usr/bin/env python3
"""Deterministic, standalone, no-network SVG motion-studies for owner visual review.

No production README or approved catalog changes. Python standard library only.
"""
from __future__ import annotations
import argparse
import hashlib
import math as m
from pathlib import Path
import random
from xml.etree import ElementTree as ET

ROOT = Path(__file__).parent
OUT = ROOT / 'assets'
SPECS = {'top':(1280,258), 'top-compact':(640,196), 'bottom':(1280,150)}
THEMES = {'living-plasma':'Living Plasma / Aurora Flux',
          'cybernetic-cathedral':'Cybernetic Cathedral / Signal Nave',
          'quantum-interference':'Quantum Interference / Spectral Loom',
          'celestial-singularity':'Celestial Singularity / Accretion Engine'}
PALETTE = ('#36E9FF','#65FFD6','#A48AFF','#FF5FD6','#E7F5FF')

def f(v): return f'{v:.2f}'.rstrip('0').rstrip('.') if isinstance(v,float) else str(v)
def e(tag, **attrs): return '<'+tag+' '+' '.join(f'{k.replace("_","-")}="{v}"' for k,v in attrs.items())+'/>'
def path(d,c,op=.5,w=.8, **attrs): return e('path',d=d,stroke=c,fill='none',opacity=f(op),stroke_width=f(w),**attrs)
def ellipse(cx,cy,rx,ry,fill,op=1,**attrs): return e('ellipse',cx=f(cx),cy=f(cy),rx=f(rx),ry=f(ry),fill=fill,opacity=f(op),**attrs)
def circ(cx,cy,r,fill,op=1,**attrs):return e('circle',cx=f(cx),cy=f(cy),r=f(r),fill=fill,opacity=f(op),**attrs)
def polyline(points): return 'M'+' L'.join(f'{f(x)} {f(y)}' for x,y in points)
def closed(points):return polyline(points)+' Z'
def grad(id, colors, rad=False):
    stops=''.join(f'<stop offset="{f(100*i/(len(colors)-1))}%" stop-color="{c}" stop-opacity="{f(op)}"/>' for i,(c,op) in enumerate(colors))
    return f'<radialGradient id="{id}" cx="50%" cy="50%" r="50%">{stops}</radialGradient>' if rad else f'<linearGradient id="{id}" x1="0%" y1="0%" x2="100%" y2="40%">{stops}</linearGradient>'

def backdrop(w,h,kind,rng):
    # Luminous clouds and particulate material, feathered to avoid harsh web-header edges.
    clouds=[]
    for i in range(18 if w>700 else 12):
        x=w*(.02+.96*rng.random());y=h*(.22+.57*rng.random())
        r=w*(.07+.15*rng.random()); ry=h*(.32+.43*rng.random())
        clouds.append(ellipse(x,y,r,ry,'url(#mist'+str(i%3)+')',.26+.27*rng.random()))
    dust=[]
    for i in range(255 if w>700 else 145):
        x=rng.random()*w;y=rng.random()*h
        dust.append(circ(x,y,.18+1.14*rng.random(),PALETTE[(i*7)%5],.10+.36*rng.random()))
    return '<g>'+''.join(clouds)+'</g><g>'+''.join(dust)+'</g>'

def living_plasma(w,h,rng):
    top=[];middle=[];front=[]
    for j in range(4):
        # Broad translucent ribbons envelope detailed intertwined filaments.
        p=[]; q=[]
        for i in range(81):
            u=i/80; x=w*u; pulse=m.exp(-((u-(.36+j*.085))/.37)**2)
            y=h*(.48 + (.11+j*.016)*m.sin(u*8.2+j*.99)*pulse + .035*m.sin(u*20+j*1.55))
            p.append((x,y-h*(.07+j*.012))); q.append((x,y+h*(.07+j*.012)))
        middle.append(e('path',d=closed(p+list(reversed(q))),fill='url(#ribbon'+str(j%2)+')',opacity=f(.27+j*.055)))
    for k in range(410 if w>700 else 295):
        b=(k/409 if w>700 else k/294)
        band=(k%4); phase=(band*.98)+(k%103)*.032
        pts=[]
        for i in range(47 if w>700 else 38):
            u=i/(46 if w>700 else 37);v=(u-.5)
            envelope=m.exp(-((u-.50)/.44)**4)
            helix=(.12+.085*m.sin(b*14+band))*m.sin(9.3*u + phase*1.23)
            fine=.018*m.sin(24*u - phase*1.4)*m.sin(4*u+phase)
            helix2=.032*m.cos(18*u+phase*.51)
            y=h*(.49 + (b-.5)*.45 + (helix+fine+helix2)*envelope)
            x=w*u+ w*.010*m.sin(13*u+phase)*envelope
            pts.append((x,y))
        color=PALETTE[[0,2,3,1][band]]
        op=(.10+.38*(1-abs(b-.5)*1.25))
        front.append(path(polyline(pts),color,op,.42+.70*(k%9==0),stroke_linecap='round'))
        if k%18==0:
            front.append(path(polyline(pts),'#DFF9FF',.17,2.3,filter='url(#softglow)'))
    # Strong energy-nexus flares and interleaved specular fragments.
    for j in range(30):
        x=w*(.13+.74*rng.random()); y=h*(.24+.52*rng.random());c=PALETTE[j%4]
        front.append(circ(x,y,1.3+1.8*rng.random(),c,.45,filter='url(#glow)'))
        front.append(path(f'M{f(x-9)} {f(y)} L{f(x+9)} {f(y)}',c,.22,.6))
    return ''.join(middle), ''.join(top+front)

def cybernetic_cathedral(w,h,rng):
    mid=w*.5;floor=h*.91
    back=[];front=[]
    # Receding vault arches; spline glass ribbing, not a ring icon.
    for j in range(70 if w>700 else 53):
        p=j/69 if w>700 else j/52
        radius=w*(.11+.40*p)
        pts=[]
        for i in range(47):
            th=m.pi*(.02+i/46*.96)
            x=mid+radius*m.cos(th)
            y=floor-h*(.20+.53*(1-p*.28))*m.sin(th) - h*(.07*(1-p))
            pts.append((x,y))
        c=PALETTE[j%4]
        front.append(path(polyline(pts),c,.14+.29*(1-p),.5+(j%9==0)*.75))
        if j%9==0:back.append(path(polyline(pts),c,.18,4.5,filter='url(#softglow)'))
    # Flying buttresses and layered optic-fiber rails from both edges.
    for side in (-1,1):
        for j in range(82 if w>700 else 50):
            t=j/(81 if w>700 else 49)
            x0=mid+side*w*(.51-.17*t)
            x1=mid+side*w*(.14+.13*t)
            y0=h*(.07+.83*t)
            y1=h*(.15+.60*(.5+.5*m.sin(t*4.2+j*.10)))
            d=f'M{f(x0)} {f(y0)} C{f(x0-side*w*.10)} {f(y0-h*.08)} {f(x1+side*w*.14)} {f(y1+h*.12)} {f(x1)} {f(y1)}'
            front.append(path(d,PALETTE[(j+int(side==1))%4],.17+.22*(j%4==0),.5+(j%11==0)*.65))
            if j%7==0:
                front.append(circ(x0,y0,1.1,PALETTE[j%4],.65))
                front.append(circ(x1,y1,1.1,PALETTE[(j+2)%4],.65))
        for j in range(18):
            u=j/17
            x=mid+side*w*(.22+.027*(j%3)); xend=mid+side*w*(.43+.07*(j%3))
            y=h*(.14+.72*u)
            d=f'M{f(x)} {f(y)} L{f(x+side*w*.06)} {f(y)} L{f(x+side*w*.075)} {f(y-h*.037)} L{f(xend)} {f(y-h*.037)}'
            front.append(path(d,PALETTE[j%4],.35,.85))
            front.append(circ(xend,y-h*.037,1.5,PALETTE[(j+1)%4],.68))
    # Central impossibly detailed signal nave with facets, ribs, a portal light well.
    for j in range(24):
        t=j/23;rx=w*(.08+.037*t);ry=h*(.33+.13*t)
        back.append(ellipse(mid,h*.52,rx,ry,'url(#gate)',.12+.055*(1-t)))
        pts=[(mid-rx,h*.89),(mid-rx,h*.28),(mid,h*.12-h*.09*t),(mid+rx,h*.28),(mid+rx,h*.89)]
        front.append(path(polyline(pts),PALETTE[j%4],.22+.45*(j%8==0),.7))
    for j in range(56):
        x=mid+(j-27.5)*w*.004; amp=h*(.31+.04*m.sin(j*.7))
        front.append(path(f'M{f(x)} {f(h*.82)} L{f(x)} {f(h*.82-amp)}', PALETTE[j%4], .12+.25*(j%6==0),.35))
    for j in range(40):
        a=2*m.pi*j/40
        x=mid+w*.086*m.cos(a);y=h*.51+h*.35*m.sin(a)
        front.append(circ(x,y,1.4,PALETTE[j%4],.75))
    return ''.join(back),''.join(front)

def quantum_interference(w,h,rng):
    under=[];top=[]; cx=w*.51
    for phasegroup in range(3):
        # Three physically distinct wavelength/phase families build moire caustics.
        for j in range(115 if w>700 else 90):
            v=j/(114 if w>700 else 89)
            pts=[]
            for k in range(47 if w>700 else 36):
                u=k/(46 if w>700 else 35)
                x=w*u
                aperture=m.exp(-((u-.51)/(.31+phasegroup*.06))**2)
                chirp=8.4 + 15.7*u + 1.7*m.sin(2*m.pi*u)
                a=(.063+.066*(1-abs(v-.5)*2))*aperture
                y=h*(.12+.74*v + a*m.sin(chirp*u*2*m.pi + v*12.2 +phasegroup*2.4)
                       +.022*aperture*m.sin(41*u+phasegroup*1.5)*(v-.5))
                if phasegroup==1: y+=h*.06*m.cos(u*11.2+v*4)*aperture
                if phasegroup==2: y+=h*.065*m.sin(u*18.1-v*5.7)*aperture
                pts.append((x,y))
            c=(PALETTE[(j//7+phasegroup)%4])
            op=.12+.25*(j%12==0)+.09*m.sin(v*m.pi)
            top.append(path(polyline(pts),c,op,.45+(j%12==0)*.52))
            if j%37==0:
                under.append(path(polyline(pts),c,.16,4,filter='url(#softglow)'))
    # Non-circular caustic cell lattices, glancing planes, bright interference loci.
    for j in range(24):
        t=j/23
        pp=[]
        for k in range(110):
            a=k/109*2*m.pi
            r=(.18+.33*t)*(1+.12*m.cos(11*a+j*.55))
            x=cx + w*r*m.cos(a); y=h*.50 +h*r*.61*m.sin(a)
            pp.append((x,y))
        top.append(path(polyline(pp),PALETTE[j%4],.09+.25*(j%8==0),.5))
    for i in range(52):
        x=w*(.13+.75*rng.random());y=h*(.13+.74*rng.random())
        top.append(circ(x,y,.5+1.4*rng.random(),PALETTE[i%4],.35+.2*rng.random()))
    return ''.join(under),''.join(top)

def celestial_singularity(w,h,rng):
    cx=w*.53;cy=h*.48;back=[];top=[]
    # Deep tilted accretion disc: multiple non-concentric orbit families and caustic perturbations.
    theta=-.21
    def xyz(radius,a,warp=0):
        x=radius*m.cos(a)*1.88
        y=radius*m.sin(a)*.57 + warp
        return cx + x*m.cos(theta)-y*m.sin(theta),cy+x*m.sin(theta)+y*m.cos(theta)
    for j in range(155 if w>700 else 120):
        t=j/(154 if w>700 else 119)
        radius=h*(.17+.88*t)
        pts=[]
        for k in range(65):
            a=(k/64)*2*m.pi +t*.45
            fluct=h*.035*m.sin(a*9+j*.17)+h*.017*m.sin(a*21-j*.12)
            pts.append(xyz(radius+fluct,a))
        c=PALETTE[(j//13 + (j%7==0))%4]
        top.append(path(polyline(pts),c,.10+.37*(j%13==0)+.13*m.sin(t*m.pi),.45+(j%19==0)*.9))
        if j%22==0:back.append(path(polyline(pts),c,.12,3.2,filter='url(#softglow)'))
    # Gravitational lens arc streamlines, bent and luminous, enveloping the aperture.
    for j in range(68 if w>700 else 50):
        t=j/(67 if w>700 else 49)
        pts=[]
        for k in range(45):
            a=-.90+m.pi*1.8*k/44
            rad=h*(.29+.9*t) + h*.028*m.sin(7*a+t*13)
            pts.append(xyz(rad,a))
        top.append(path(polyline(pts),PALETTE[j%4],.10+.20*(j%9==0),.55))
    # Blue/violet bipolar jets: streaks disperse as they leave lens.
    for side in (-1,1):
        for j in range(38):
            t=(j-18.5)/37
            pts=[]
            for k in range(23):
                u=k/22;cy0=cy+side*h*(.11+.73*u)
                x=cx + w*(t*.004+u*t*.13 + .015*m.sin(u*7+j*.25))
                pts.append((x,cy0))
            top.append(path(polyline(pts),PALETTE[(j+int(side==1))%4],.10+.17*(j%7==0),.5))
    # Bright outer lens and central black silhouette, with tiny photon highlights.
    top.append(ellipse(cx,cy,h*.245,h*.20,'url(#horizon)',1,filter='url(#glow)'))
    top.append(ellipse(cx,cy,h*.216,h*.165,'#02020B',1))
    top.append(ellipse(cx,cy,h*.169,h*.135,'#000007',1))
    top.append(path(f'M{f(cx-h*.16)} {f(cy+h*.06)} Q{f(cx)} {f(cy+h*.27)} {f(cx+h*.16)} {f(cy+h*.06)}','#C8FBFF',.27,1.1))
    for j in range(340 if w>700 else 210):
        a=rng.random()*2*m.pi
        radius=h*(.3+1.1*rng.random())
        x,y=xyz(radius,a, warp=h*.03*m.sin(a*13))
        if 0<x<w and 0<y<h:
            top.append(circ(x,y,.3+1.2*rng.random(),PALETTE[j%4],.18+.42*rng.random()))
    return ''.join(back),''.join(top)

SCENES={'living-plasma':living_plasma,'cybernetic-cathedral':cybernetic_cathedral,'quantum-interference':quantum_interference,'celestial-singularity':celestial_singularity}

def document(scene,surface):
    w,h=SPECS[surface]; rng=random.Random(int(hashlib.sha256((scene+surface).encode()).hexdigest()[:12],16))
    title=THEMES[scene]
    defs=(grad('bg',[('#030713',1),('#0A1129',1),('#120923',1),('#020713',1)])
        +grad('mist0',[('#0A1C38',0),('#16DBFF',.45),('#721AF7',.18),('#00010D',0)],True)
        +grad('mist1',[('#000',0),('#F92DCE',.45),('#6422E9',.25),('#000',0)],True)
        +grad('mist2',[('#000',0),('#21FFC2',.28),('#3969FF',.22),('#000',0)],True)
        +grad('ribbon0',[('#37EFFF',0),('#37EFFF',.29),('#9D6CFF',.45),('#FC54D1',.23),('#37EFFF',0)])
        +grad('ribbon1',[('#FC54D1',0),('#FF58DE',.30),('#62FFEA',.27),('#47DAFF',.33),('#FC54D1',0)])
        +grad('gate',[('#3EE9FF',0),('#BC70FF',.06),('#61FBF4',.15),('#9C7CFF',.05),('#36E9FF',0)],True)
        +grad('horizon',[('#10DDFC',.20),('#D6F9FF',.94),('#FF58D4',.74),('#070216',0)],True)
        +'<filter id="softglow" x="-40%" y="-100%" width="180%" height="300%"><feGaussianBlur stdDeviation="3"/></filter>'
        +'<filter id="glow" x="-110%" y="-110%" width="320%" height="320%"><feGaussianBlur stdDeviation="2.2"/></filter>'
        +'<linearGradient id="feather"><stop stop-color="black"/><stop offset=".04" stop-color="white"/><stop offset=".96" stop-color="white"/><stop offset="1" stop-color="black"/></linearGradient>'
        +f'<mask id="edge"><rect width="{w}" height="{h}" fill="url(#feather)"/></mask>'
        +'<filter id="astral-grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".006 .032" numOctaves="3" seed="22" stitchTiles="stitch" result="t"/><feColorMatrix in="t" type="matrix" values=".0 .7 .2 0 0 .1 .2 .5 0 0 .6 .1 .3 0 0 .3 0 0 .3 -.17"/></filter>')
    behind,front=SCENES[scene](w,h,rng)
    dusty=backdrop(w,h,scene,rng)
    # Keep all artwork on GitHub without external dependencies; animated overlay can be hidden.
    css='''<style>.motion{display:inline}.still{display:none}.current{stroke-dasharray:7 33;animation:flow 12s linear infinite}.pulse{animation:pulse 7.3s ease-in-out infinite}@keyframes flow{to{stroke-dashoffset:-240}}@keyframes pulse{0%,100%{opacity:.68}50%{opacity:1}}@media(prefers-reduced-motion:reduce){.motion{display:none!important}.still{display:inline!important}.current,.pulse{animation:none!important}}</style>'''
    base=f'<rect width="{w}" height="{h}" fill="url(#bg)"/><rect width="{w}" height="{h}" filter="url(#astral-grain)" opacity=".30"/>'
    shape=(f'<defs><g id="under-art">{behind}</g><g id="front-art">{front}</g></defs>'
       f'<g mask="url(#edge)">{dusty}'
       f'<g class="motion"><use href="#under-art"><animateTransform attributeName="transform" type="translate" values="0 0;4 -2;0 0;-4 2;0 0" dur="19s" repeatCount="indefinite"/></use><use href="#front-art"><animateTransform attributeName="transform" type="translate" values="0 0;-5 2;0 0;5 -2;0 0" dur="13s" repeatCount="indefinite"/></use></g>'
       f'<g class="still"><use href="#under-art"/><use href="#front-art"/></g></g>')
    # Split the static identity from animated photon layer for no double-geometry:
    # the base is always visible; only fine highlight streams oscillate.
    highlights=[]
    for k in range(23 if w>700 else 12):
        y=h*(.16+.70*k/(22 if w>700 else 11))
        x=w*(.04+.17*rng.random())
        highlights.append(path(f'M{f(x)} {f(y)} Q{f(w*.50)} {f(y-22*m.sin(k))} {f(w*.96)} {f(y-5*m.sin(k*.5))}', PALETTE[k%4],.08,.6))
    extras='<g class="motion current" mask="url(#edge)">'+''.join(highlights)+'</g>'
    extras+='<g class="motion pulse" opacity=".6">'+ellipse(w*.51,h*.48,w*.15,h*.51,'url(#mist0)',.22)+'</g>'
    # SMIL translates a lightweight luminous overlay rather than CPU-heavy full mesh.
    extras+='<g class="motion" opacity=".30">'+ellipse(w*.51,h*.49,w*.12,h*.35,'url(#mist1)',.37)+f'<animateTransform attributeName="transform" type="translate" values="{-w*.012:.2f} 0;{w*.012:.2f} 0;{-w*.012:.2f} 0" dur="17s" repeatCount="indefinite"/></g>'
    des=f'Original generative vector motion study for visual approval: {title}. Dense self-contained luminous fields with coordinated movement, responsive composition, accessible static fallback. Not in the active GitHub banner rotation.'
    svg=f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc" data-review-art="cinematic-v3" data-scene="{scene}" data-surface="{surface}"><title id="title">{title} — {surface}</title><desc id="desc">{des}</desc><defs>{defs}</defs>{css}{base}{shape}{extras}</svg>\n'
    ET.fromstring(svg)
    return svg

def build():
    OUT.mkdir(exist_ok=True)
    return {f'{i:02d}-{scene}-{surface}.svg':document(scene,surface) for i,scene in enumerate(THEMES,5) for surface in SPECS}

def check(assets):
    bad=[]
    for name,s in assets.items():
        p=OUT/name
        if not p.exists() or p.read_text()!=s:bad.append(name)
        root=ET.fromstring(s)
        assert len(root.findall('.//{http://www.w3.org/2000/svg}path'))>100,(name,'too few paths')
        assert '<script' not in s and 'http://' not in s.replace('xmlns="http://www.w3.org/2000/svg"','')
        assert 'prefers-reduced-motion' in s
        assert len(s.encode('utf8'))<410000,(name,len(s))
    if bad:raise SystemExit('Generated SVG drift: '+', '.join(bad))
    print('PASS 12 deterministic XML/SVG artworks, review-only, bounded, scriptless, accessible')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true'); a=ap.parse_args()
    assets=build()
    if not a.check:
        for name,s in assets.items(): (OUT/name).write_text(s,encoding='utf-8')
    check(assets)
    for name,s in assets.items():print(name,len(s.encode()))
if __name__=='__main__':main()