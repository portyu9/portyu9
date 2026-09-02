import { writeFile } from "node:fs/promises";

const owner = process.env.PROFILE_OWNER || "portyu9";
const token = process.env.GITHUB_TOKEN || "";
const headers = {
  "Accept": "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": `${owner}-profile-signal`
};
if (token) headers.Authorization = `Bearer ${token}`;

async function fetchPublicRepos() {
  const all = [];
  for (let page = 1; page <= 10; page += 1) {
    const url = `https://api.github.com/users/${encodeURIComponent(owner)}/repos?per_page=100&page=${page}&type=owner&sort=full_name`;
    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`GitHub API ${response.status}: ${await response.text()}`);
    }
    const batch = await response.json();
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}

function isQeSystem(repo) {
  return !repo.fork && (
    repo.name === "ai-qa-automation" ||
    repo.name.startsWith("qa-automation-")
  );
}

function domainFor(name) {
  if (name === "ai-qa-automation") return "AI";
  if (/(playwright|cypress|selenium)/.test(name) && !/(visual|accessibility)/.test(name)) return "WEB";
  if (/(postman|restassured|supertest|graphql)/.test(name)) return "API";
  if (/mobile-appium/.test(name)) return "MOBILE";
  if (/load-k6/.test(name)) return "PERFORMANCE";
  if (/(visual|accessibility)/.test(name)) return "ACCESSIBILITY";
  if (/python-pytest/.test(name)) return "FOUNDATIONS";
  return "OTHER";
}

function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function signalPath(count) {
  const points = [];
  const width = 790;
  const startX = 650;
  const baseline = 132;
  for (let i = 0; i < Math.max(count, 2); i += 1) {
    const x = startX + (width * i) / Math.max(count - 1, 1);
    const y = baseline - (26 + ((i * 37) % 58));
    points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  }
  return points.join(" ");
}

function repoNodes(repos) {
  const width = 790;
  const startX = 650;
  const baseline = 132;
  return repos.map((repo, i) => {
    const x = startX + (width * i) / Math.max(repos.length - 1, 1);
    const y = baseline - (26 + ((i * 37) % 58));
    const color = i < repos.length / 2 ? "#c94cff" : "#00d9ff";
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4.2" fill="${color}" filter="url(#g)"/>`;
  }).join("");
}

const repos = (await fetchPublicRepos()).filter(isQeSystem).sort((a, b) => a.name.localeCompare(b.name));
const domains = [...new Set(repos.map((repo) => domainFor(repo.name)).filter((d) => d !== "OTHER"))].sort();

if (repos.length === 0) {
  throw new Error("No public quality-engineering repositories matched the profile contract.");
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="230" viewBox="0 0 1600 230" role="img" aria-labelledby="title desc">
  <title id="title">${esc(owner)} public quality-engineering repository signal</title>
  <desc id="desc">A generated pure-vector signal summarizing ${repos.length} public quality-engineering systems across ${domains.length} engineering domains.</desc>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#03040b"/><stop offset="1" stop-color="#03101f"/></linearGradient>
    <linearGradient id="s" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ff3df2"/><stop offset=".48" stop-color="#7c4dff"/><stop offset="1" stop-color="#00e5ff"/></linearGradient>
    <filter id="g"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <pattern id="grid" width="26" height="26" patternUnits="userSpaceOnUse"><path d="M26 0H0V26" fill="none" stroke="#6e9dff" stroke-opacity=".045"/></pattern>
  </defs>
  <rect x="4" y="4" width="1592" height="222" rx="22" fill="url(#bg)" stroke="url(#s)" stroke-opacity=".42" stroke-width="2"/>
  <rect x="4" y="4" width="1592" height="222" rx="22" fill="url(#grid)"/>
  <path d="M52 50 H420 L440 70 H560" fill="none" stroke="#c547ff" stroke-opacity=".45"/>
  <circle cx="52" cy="50" r="3.5" fill="#ff3df2" filter="url(#g)"/>
  <text x="70" y="56" fill="#d8cbff" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="18" font-weight="750" letter-spacing="5">REPOSITORY SIGNAL // LIVE PUBLIC INDEX</text>

  <g font-family="Inter,Segoe UI,system-ui,sans-serif">
    <text x="72" y="128" fill="url(#s)" font-size="50" font-weight="820">${repos.length}</text>
    <text x="147" y="111" fill="#f1f7ff" font-size="14" font-weight="750" letter-spacing="2.5">PUBLIC QE</text>
    <text x="147" y="135" fill="#a9bad0" font-size="13" font-weight="650" letter-spacing="2">SYSTEMS</text>

    <path d="M294 86 V153" stroke="#47629b" stroke-opacity=".45"/>
    <text x="329" y="128" fill="url(#s)" font-size="50" font-weight="820">${domains.length}</text>
    <text x="402" y="111" fill="#f1f7ff" font-size="14" font-weight="750" letter-spacing="2.5">QUALITY</text>
    <text x="402" y="135" fill="#a9bad0" font-size="13" font-weight="650" letter-spacing="2">DOMAINS</text>

    <text x="72" y="184" fill="#8ca1bb" font-size="11" font-weight="600" letter-spacing="1.5">SOURCE CONTRACT: ai-qa-automation + qa-automation-*</text>
    <text x="72" y="203" fill="#677d99" font-size="10" font-weight="550" letter-spacing="1.1">Generated from GitHub public repository metadata; no vanity score, synthetic pass rate, or fabricated performance metric.</text>
  </g>

  <polyline points="${signalPath(repos.length)}" fill="none" stroke="url(#s)" stroke-width="2.3" stroke-linejoin="round" stroke-linecap="round" filter="url(#g)"/>
  <path d="M650 151 H1440" stroke="#3a5b9c" stroke-opacity=".32"/>
  ${repoNodes(repos)}
  <text x="650" y="184" fill="#9aaec7" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="10.5" font-weight="650" letter-spacing="1.7">${esc(domains.join("  •  "))}</text>
  <text x="1440" y="204" text-anchor="end" fill="#6d819b" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="10" font-weight="600" letter-spacing="1.4">DETERMINISTIC PROFILE TELEMETRY</text>
</svg>`;

await writeFile("assets/repository-signal.svg", svg, "utf8");
console.log(`Generated assets/repository-signal.svg from ${repos.length} QE repositories across ${domains.length} domains.`);
