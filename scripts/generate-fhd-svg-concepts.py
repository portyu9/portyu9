from pathlib import Path
import math
from matplotlib.textpath import TextPath
from matplotlib.font_manager import FontProperties
from matplotlib.path import Path as MplPath

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "concepts" / "profile-svg-fhd"
OUT.mkdir(parents=True, exist_ok=True)

FP_BOLD = FontProperties(family="Noto Sans Display", weight="bold")
FP_REG = FontProperties(family="Noto Sans Display", weight="regular")

def fmt(v):
    s=f"{float(v):.2f}".rstrip("0").rstrip(".")
    return s or "0"

def path_to_svg(path):
    out=[]
    for verts,code in path.iter_segments(curves=True,simplify=False):
        if code==MplPath.MOVETO:
            x,y=verts; out.append(f"M{fmt(x)} {fmt(y)}")
        elif code==MplPath.LINETO:
            x,y=verts; out.append(f"L{fmt(x)} {fmt(y)}")
        elif code==MplPath.CURVE3:
            x1,y1,x2,y2=verts; out.append(f"Q{fmt(x1)} {fmt(y1)} {fmt(x2)} {fmt(y2)}")
        elif code==MplPath.CURVE4:
            x1,y1,x2,y2,x3,y3=verts; out.append(f"C{fmt(x1)} {fmt(y1)} {fmt(x2)} {fmt(y2)} {fmt(x3)} {fmt(y3)}")
        elif code==MplPath.CLOSEPOLY:
            out.append("Z")
    return "".join(out)

_cache={}
def text_data(text, bold=True):
    key=(text,bold)
    if key not in _cache:
        fp=FP_BOLD if bold else FP_REG
        p=TextPath((0,0),text,prop=fp,size=1,usetex=False)
        _cache[key]=(path_to_svg(p),p.get_extents())
    return _cache[key]

def fit(text,box,max_size,min_size=18,bold=True):
    _,bb=text_data(text,bold)
    return min(max_size,max(min_size,box/bb.width)) if bb.width else max_size

def text(text,x,y,size,fill="#fff",bold=True,anchor="start",opacity=1):
    d,bb=text_data(text,bold)
    w=bb.width*size
    if anchor=="middle":
        tx=x-w/2-bb.x0*size
    elif anchor=="end":
        tx=x-w-bb.x0*size
    else:
        tx=x-bb.x0*size
    return f'<path d="{d}" transform="translate({fmt(tx)} {fmt(y)}) scale({fmt(size)} {fmt(-size)})" fill="{fill}" opacity="{opacity}"/>'

def defs(extra=""):
    return f'''<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#02030A"/><stop offset=".52" stop-color="#06091A"/><stop offset="1" stop-color="#021126"/></linearGradient>
<linearGradient id="spectral" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#FF3DF2"/><stop offset=".34" stop-color="#B64CFF"/><stop offset=".68" stop-color="#4B86FF"/><stop offset="1" stop-color="#00E5FF"/></linearGradient>
<linearGradient id="glass" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#11183A" stop-opacity=".92"/><stop offset=".55" stop-color="#070B1C" stop-opacity=".86"/><stop offset="1" stop-color="#031229" stop-opacity=".94"/></linearGradient>
<radialGradient id="nebM"><stop offset="0" stop-color="#FF00E6" stop-opacity=".25"/><stop offset="1" stop-color="#02030A" stop-opacity="0"/></radialGradient>
<radialGradient id="nebC"><stop offset="0" stop-color="#008CFF" stop-opacity=".26"/><stop offset="1" stop-color="#02030A" stop-opacity="0"/></radialGradient>
<filter id="glowM" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glowC" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="7" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="soft" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="40"/></filter>
<pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse"><path d="M48 0H0V48" fill="none" stroke="#6E9DFF" stroke-opacity=".045"/></pattern>
<pattern id="dots" width="18" height="18" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.1" fill="#6EBEFF" opacity=".08"/></pattern>{extra}</defs>'''

def background():
    return '''<rect width="1920" height="1080" fill="url(#bg)"/><rect width="1920" height="1080" fill="url(#grid)"/><rect width="1920" height="1080" fill="url(#dots)" opacity=".55"/>
<ellipse cx="1500" cy="60" rx="620" ry="270" fill="url(#nebM)" filter="url(#soft)"/><ellipse cx="1760" cy="240" rx="470" ry="300" fill="url(#nebC)" filter="url(#soft)"/>
<rect x="18" y="18" width="1884" height="1044" rx="34" fill="none" stroke="url(#spectral)" stroke-opacity=".52" stroke-width="2"/>
<path d="M34 184V82L98 24h460l42 42h280l42 42h262" fill="none" stroke="#BA45FF" stroke-opacity=".55" stroke-width="2"/>
<path d="M34 218V126l74-72h602" fill="none" stroke="#00DFFF" stroke-opacity=".42" stroke-width="2"/>
<path d="M1886 260V82l-56-56h-294" fill="none" stroke="#00DFFF" stroke-opacity=".46" stroke-width="2"/>'''

def wrap(title,desc,body,extra=""):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080" preserveAspectRatio="xMidYMid meet" role="img" aria-labelledby="title desc"><title id="title">{title}</title><desc id="desc">{desc}</desc>{defs(extra)}{body}</svg>'

def save(name,svg):
    (OUT/name).write_text(svg,encoding="utf-8")

NAME="Ƴunior Ƥortal"
ROLE="QUALITY ENGINEERING • AUTOMATION ARCHITECTURE • AI-ENABLED SYSTEMS"

# 1 — Orbital Core
b=[background(),text("QUALITY ENGINEERING // ORBITAL CORE",90,150,34,"#DCD7FF"),text(NAME,90,330,86,"url(#spectral)")]
b.append(text("ENGINEERING CONFIDENCE",90,445,fit("ENGINEERING CONFIDENCE",900,72,56),"#F7FBFF"))
b.append(text(ROLE,94,520,fit(ROLE,930,30,22),"#BFD1E8"))
b.append('<path d="M86 570H1010l24 24v108l-24 24H86l-24-24V594Z" fill="url(#glass)" stroke="url(#spectral)" stroke-opacity=".65" stroke-width="2"/>')
b.append(text("EVIDENCE → ATTRIBUTION → CONFIDENCE",118,635,fit("EVIDENCE → ATTRIBUTION → CONFIDENCE",840,30,24),"#F1F6FF"))
b.append(text("Reduce uncertainty by making every conclusion traceable.",118,686,fit("Reduce uncertainty by making every conclusion traceable.",840,29,23),"#9FB4CE",False))
cx,cy=1470,515
b.append(f'<circle cx="{cx}" cy="{cy}" r="318" fill="url(#nebC)" opacity=".6"/>')
for r,col,op,dash in [(275,"#2D4A9B",".4",None),(238,"#744CFF",".5","8 12"),(198,"#00DFFF",".55",None),(154,"#C844FF",".55","5 10")]:
    da=f' stroke-dasharray="{dash}"' if dash else ""
    b.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-opacity="{op}" stroke-width="2"{da}/>')
b += [f'<path d="M{cx} {cy-238} A238 238 0 0 1 {cx+219} {cy-92}" fill="none" stroke="#00E5FF" stroke-width="12" stroke-linecap="round" filter="url(#glowC)"/>',
      f'<path d="M{cx-224} {cy-82} A238 238 0 0 1 {cx-50} {cy-233}" fill="none" stroke="#FF3DF2" stroke-width="12" stroke-linecap="round" filter="url(#glowM)"/>',
      f'<polygon points="{cx},{cy-100} {cx+86},{cy-50} {cx+86},{cy+50} {cx},{cy+100} {cx-86},{cy+50} {cx-86},{cy-50}" fill="url(#glass)" stroke="url(#spectral)" stroke-width="4"/>',
      text("QE",cx,cy+18,72,"#F7FBFF",True,"middle")]
for lab,x,y,col in [("EVIDENCE",1190,875,"#EAB7FF"),("ATTRIBUTION",1470,930,"#C5C7FF"),("CONFIDENCE",1750,875,"#9DEFFF")]:
    b.append(text(lab,x,y,fit(lab,300,28,23),col,True,"middle"))
b.append('<path d="M70 905C230 905 260 840 390 840S560 960 705 960 900 850 1040 850" fill="none" stroke="url(#spectral)" stroke-width="4" filter="url(#glowC)"/>')
save("01-orbital-core.svg",wrap(f"{NAME} — Orbital Core","FHD pure-vector Quality Engineering identity with outlined typography and an orbital proof core.","".join(b)))

# 2 — Signal Horizon
b=[background(),text("QUALITY ENGINEERING // SIGNAL HORIZON",960,150,34,"#DAD8FF",True,"middle"),text(NAME,960,330,92,"url(#spectral)",True,"middle")]
b.append(text("DECISION-GRADE QUALITY SYSTEMS",960,440,fit("DECISION-GRADE QUALITY SYSTEMS",1500,66,50),"#F7FBFF",True,"middle"))
b.append(text("TRACEABLE EVIDENCE • EXPLICIT ORACLES • ATTRIBUTABLE FAILURE",960,515,fit("TRACEABLE EVIDENCE • EXPLICIT ORACLES • ATTRIBUTABLE FAILURE",1450,28,22),"#B7C9DF",True,"middle"))
b.append('<path d="M80 685H1840" stroke="#244A8D" stroke-opacity=".45" stroke-width="2"/>')
for i,phase in enumerate([0,.8,1.6]):
    pts=[f"{x},{685+60*math.sin((x/120)+phase)*(0.85 if i==0 else 0.45):.1f}" for x in range(80,1841,20)]
    col=["#FF3DF2","#7264FF","#00E5FF"][i]
    b.append(f'<polyline points="{" ".join(pts)}" fill="none" stroke="{col}" stroke-opacity="{0.7 if i==0 else 0.5}" stroke-width="{4 if i==0 else 2.5}" filter="url(#glowC)"/>')
labels=["AI QUALITY","WEB","API + CONTRACT","MOBILE","PERFORMANCE","ACCESSIBILITY"]
for i,lab in enumerate(labels):
    x=100+i*290; stroke="#C74CFF" if i<3 else "#00CFFF"
    b.append(f'<path d="M{x} 805h254l16 16v128l-16 16H{x}l-16-16V821Z" fill="url(#glass)" stroke="{stroke}" stroke-opacity=".55" stroke-width="2"/>')
    b.append(text(lab,x+127,885,fit(lab,220,28,20),"#F2F7FF",True,"middle"))
    b.append(f'<circle cx="{x+127}" cy="930" r="6" fill="{("#E04CFF" if i<3 else "#00E5FF")}" filter="url(#glowC)"/>')
save("02-signal-horizon.svg",wrap(f"{NAME} — Signal Horizon","FHD pure-vector signal-wave Quality Engineering identity with large outlined typography and six domain modules.","".join(b)))

# 3 — Glass Console
b=[background(),text("QUALITY ENGINEERING // GLASS CONSOLE",90,145,34,"#DCD8FF"),text(NAME,90,315,86,"url(#spectral)"),text("ARCHITECT FOR",90,410,54,"#F7FBFF")]
b.append(text("ENGINEERING CONFIDENCE",90,475,fit("ENGINEERING CONFIDENCE",820,54,42),"#F7FBFF"))
sub="SYSTEMS THAT MAKE PROOF — AND ITS LIMITS — EXPLICIT."
b.append(text(sub,94,535,fit(sub,820,29,22),"#B4C6DC"))
b.append('<path d="M82 595H850l24 24v148l-24 24H82l-24-24V619Z" fill="url(#glass)" stroke="url(#spectral)" stroke-opacity=".58" stroke-width="2"/>')
b += [text("ENGINEERING THESIS",118,655,28,"#D9C5FF"),text("Reduce uncertainty. Preserve attribution.",118,710,fit("Reduce uncertainty. Preserve attribution.",680,34,26),"#F3F7FF"),
      text("Earn confidence with evidence that survives scrutiny.",118,760,fit("Earn confidence with evidence that survives scrutiny.",690,29,23),"#91A7C2",False)]
panels=[("EVIDENCE","TRACEABLE","#FF58F0"),("ORACLES","EXPLICIT","#9E72FF"),("FAILURE","ATTRIBUTABLE","#5B8CFF"),("CONFIDENCE","EARNED","#00DFFF")]
for idx,(top,bottom,col) in enumerate(panels):
    row=idx//2; ci=idx%2; x=1050+ci*390; y=260+row*310
    b.append(f'<path d="M{x} {y}h330l24 24v190l-24 24h-330l-24-24V{y+24}Z" fill="url(#glass)" stroke="{col}" stroke-opacity=".62" stroke-width="2.4"/>')
    b.append(f'<circle cx="{x+42}" cy="{y+48}" r="10" fill="{col}" filter="url(#glowC)"/>')
    b.append(text(top,x+42,y+122,fit(top,280,34,26),"#F5F8FF"))
    b.append(text(bottom,x+42,y+178,fit(bottom,278,30,21),col))
    b.append(f'<path d="M{x+42} {y+210}h245" stroke="{col}" stroke-opacity=".32" stroke-width="2"/>')
save("03-glass-console.svg",wrap(f"{NAME} — Glass Console","FHD pure-vector executive glass-console Quality Engineering identity with four large doctrine panels and outlined typography.","".join(b)))

# 4 — Constellation Matrix
b=[background(),text("QUALITY ENGINEERING // CONSTELLATION MATRIX",960,145,fit("QUALITY ENGINEERING // CONSTELLATION MATRIX",1300,34,27),"#DCD8FF",True,"middle"),
   text(NAME,960,295,82,"url(#spectral)",True,"middle"),text("A SYSTEM OF INDEPENDENT SIGNALS — ONE ENGINEERING THESIS",960,385,fit("A SYSTEM OF INDEPENDENT SIGNALS — ONE ENGINEERING THESIS",1550,40,31),"#F4F8FF",True,"middle")]
cx,cy=960,650
b += [f'<circle cx="{cx}" cy="{cy}" r="145" fill="url(#glass)" stroke="url(#spectral)" stroke-width="3"/>',f'<circle cx="{cx}" cy="{cy}" r="108" fill="none" stroke="#00DFFF" stroke-opacity=".35" stroke-dasharray="7 12" stroke-width="2"/>',text("QE",cx,cy+8,62,"#F7FBFF",True,"middle"),text("CORE",cx,cy+61,26,"#96EFFF",True,"middle")]
nodes=[("AI QUALITY",420,555,"#E24CFF"),("WEB",330,780,"#B64CFF"),("API + CONTRACT",660,825,"#7C5CFF"),("MOBILE",1260,825,"#4D7CFF"),("PERFORMANCE",1590,780,"#1CAFFF"),("ACCESSIBILITY",1500,555,"#00E5FF")]
for lab,x,y,col in nodes:
    b.append(f'<path d="M{cx} {cy}L{x} {y}" stroke="{col}" stroke-opacity=".35" stroke-width="2"/><circle cx="{x}" cy="{y}" r="78" fill="url(#glass)" stroke="{col}" stroke-opacity=".68" stroke-width="2.5"/><circle cx="{x}" cy="{y}" r="10" fill="{col}" filter="url(#glowC)"/>')
    b.append(text(lab,x,y+122,fit(lab,250,28,21),"#EAF2FF",True,"middle"))
b.append('<path d="M300 982H1620" stroke="#3B5A9C" stroke-opacity=".3" stroke-width="2"/>')
foot="TEST AT THE LOWEST LAYER THAT CAN CONCLUSIVELY PROVE THE REQUIREMENT."
b.append(text(foot,960,1028,fit(foot,1400,27,22),"#8EA4BF",True,"middle"))
save("04-constellation-matrix.svg",wrap(f"{NAME} — Constellation Matrix","FHD pure-vector Quality Engineering portfolio constellation with outlined typography and spatially separated domain labels.","".join(b)))

# 5 — Prism Minimal
extra='<linearGradient id="prismA" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FF3DF2" stop-opacity=".72"/><stop offset="1" stop-color="#5B73FF" stop-opacity=".18"/></linearGradient><linearGradient id="prismB" x1="1" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#00E5FF" stop-opacity=".76"/><stop offset="1" stop-color="#7050FF" stop-opacity=".20"/></linearGradient>'
b=[background(),text("QUALITY ENGINEERING // PRISM",92,150,34,"#DCD8FF"),text(NAME,92,340,100,"url(#spectral)")]
for txt,y in [("FROM CHANGE",470),("TO PROOF",545),("TO DECISION",620)]: b.append(text(txt,92,y,58,"#F7FBFF"))
b.append(text("NO VANITY METRICS. NO AMBIGUOUS GREEN.",96,700,fit("NO VANITY METRICS. NO AMBIGUOUS GREEN.",650,30,23),"#A8BDD6"))
b.append('<polygon points="1230,240 1650,520 1230,800 810,520" fill="none" stroke="url(#spectral)" stroke-width="4" filter="url(#glowC)"/><polygon points="1230,240 1230,800 810,520" fill="url(#prismA)" stroke="#C847FF" stroke-opacity=".55" stroke-width="2"/><polygon points="1230,240 1650,520 1230,800" fill="url(#prismB)" stroke="#00DFFF" stroke-opacity=".55" stroke-width="2"/>')
b += [text("CHANGE",1230,200,34,"#F2C2FF",True,"middle"),text("PROOF",1705,530,34,"#A8ECFF",True,"middle"),text("DECISION",1230,875,34,"#D6DAFF",True,"middle")]
for y,col in [(950,"#FF3DF2"),(978,"#7C4DFF"),(1006,"#00E5FF")]: b.append(f'<path d="M520 {y}H1700" stroke="{col}" stroke-opacity=".34" stroke-width="3"/>')
save("05-prism-minimal.svg",wrap(f"{NAME} — Prism Minimal","FHD pure-vector minimal prism identity mapping change to proof to decision with outlined typography.","".join(b),extra))

# 6 — Circuit Blueprint
b=[background(),text("QUALITY ENGINEERING // CIRCUIT BLUEPRINT",90,145,fit("QUALITY ENGINEERING // CIRCUIT BLUEPRINT",900,34,27),"#DCD8FF"),text(NAME,90,300,84,"url(#spectral)"),
   text("A DETERMINISTIC PATH FROM CHANGE TO CONFIDENCE",90,405,fit("A DETERMINISTIC PATH FROM CHANGE TO CONFIDENCE",1650,50,36),"#F7FBFF")]
stages=[("CHANGE","SUBJECT + REVISION","#E34CFF"),("EXECUTE","CONTROLLED BOUNDARY","#B24CFF"),("EVIDENCE","TRACEABLE ARTIFACTS","#656CFF"),("VALIDATE","EXPLICIT ORACLE","#2D9CFF"),("CONFIDENCE","ATTRIBUTABLE CLAIM","#00DFFF")]
x0=90; y=585; gap=24; w=330; h=230
for i,(top,bottom,col) in enumerate(stages):
    x=x0+i*(w+gap)
    if i>0: b.append(f'<path d="M{x-gap} {y+h/2}H{x}" stroke="{col}" stroke-opacity=".65" stroke-width="3"/><polygon points="{x-8},{y+h/2-8} {x+5},{y+h/2} {x-8},{y+h/2+8}" fill="{col}"/>')
    b.append(f'<path d="M{x} {y}h306l24 24v182l-24 24H{x}l-24-24V609Z" fill="url(#glass)" stroke="{col}" stroke-opacity=".63" stroke-width="2.3"/><circle cx="{x+44}" cy="{y+48}" r="11" fill="{col}" filter="url(#glowC)"/>')
    b.append(text(top,x+44,y+118,fit(top,245,34,25),"#F6F9FF"))
    b.append(text(bottom,x+44,y+174,fit(bottom,245,23,17),col))
b.append('<path d="M90 900H1830" stroke="#3B5A9C" stroke-opacity=".35" stroke-width="2"/>')
closing="REASON DELIBERATELY. EXECUTE DETERMINISTICALLY. PROVE WITH ATTRIBUTABLE EVIDENCE."
b.append(text(closing,960,980,fit(closing,1550,30,23),"#A7BBD3",True,"middle"))
save("06-circuit-blueprint.svg",wrap(f"{NAME} — Circuit Blueprint","FHD pure-vector deterministic Quality Engineering pipeline with outlined typography and large, fixed stage cards.","".join(b)))

print("Generated six FHD SVG concepts in",OUT)
