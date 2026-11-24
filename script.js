const COLORS = { "Application":"#38bdf8", "Transport":"#34d399", "Internet":"#fbbf24", "Network Access":"#f472b6" };
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));

async function api(url) {
  const r = await fetch(url);
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function kv(obj) {
  return '<table class="kv">' + Object.entries(obj).map(([k, v]) => {
    if (v && typeof v === "object" && !Array.isArray(v)) v = Object.entries(v).map(([a, b]) => `${a}: ${b}`).join("\n");
    return `<tr><th>${esc(k)}</th><td style="white-space:pre-wrap">${esc(Array.isArray(v) ? v.join(", ") : v)}</td></tr>`;
  }).join("") + "</table>";
}

async function runTool(el, fn) {
  el.innerHTML = '<span class="muted">Working...</span>';
  try { el.innerHTML = await fn(); }
  catch (e) { el.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}

/* ---------- Theme ---------- */
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
$("theme").onclick = () => {
  const t = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("theme", t); } catch (e) {}
  drawPing();
};

/* ---------- Protocol explorer ---------- */
let protocols = [], activeLayer = "All";

function renderFilters() {
  $("filters").innerHTML = "";
  ["All", ...Object.keys(COLORS)].forEach(n => {
    const b = document.createElement("button");
    b.className = "chip" + (n === activeLayer ? " active" : "");
    b.textContent = n;
    b.onclick = () => { activeLayer = n; renderFilters(); renderCards(); };
    $("filters").appendChild(b);
  });
}

function renderCards() {
  const q = $("search").value.trim().toLowerCase();
  const list = protocols.filter(p => (activeLayer === "All" || p.layer === activeLayer) &&
    `${p.name} ${p.full} ${p.port} ${p.desc} ${p.transport}`.toLowerCase().includes(q));
  $("grid").innerHTML = "";
  list.forEach(p => {
    const d = document.createElement("div");
    d.className = "card";
    d.style.setProperty("--c", COLORS[p.layer]);
    d.innerHTML = `<h3>${esc(p.name)}</h3><small>${esc(p.full)}</small><br>
      <span class="tag">${p.layer} layer</span>${p.port !== "-" ? `<span class="tag">Port ${esc(p.port)}</span>` : ""}
      ${p.transport !== "-" ? `<span class="tag">${esc(p.transport)}</span>` : ""}
      <div class="more">${esc(p.desc)}</div>`;
    d.onclick = () => d.classList.toggle("open");
    $("grid").appendChild(d);
  });
  $("empty").classList.toggle("hidden", list.length > 0);
}

/* ---------- Packet journey ---------- */
const STAGES = [
  ["Application", "creates the data (a web request)"],
  ["Transport", "wraps it in a TCP segment: ports and sequence number"],
  ["Internet", "wraps it in an IP packet: source and destination IP"],
  ["Network Access", "wraps it in an Ethernet frame and sends bits on the wire"],
];
let journeyBusy = false;
async function journey() {
  if (journeyBusy) return;
  journeyBusy = true; $("journeyBtn").disabled = true;
  const layers = document.querySelectorAll(".stack .layer");
  const order = [0, 1, 2, 3, 3, 2, 1, 0];
  for (let s = 0; s < order.length; s++) {
    const i = order[s];
    layers.forEach((l, idx) => l.classList.toggle("active", idx === i));
    $("journeyCap").textContent = s < 4
      ? `Sender - ${STAGES[i][0]} layer ${STAGES[i][1]}.`
      : `Receiver - ${STAGES[i][0]} layer removes its header and passes the data up.`;
    await sleep(1000);
  }
  layers.forEach(l => l.classList.remove("active"));
  $("journeyCap").textContent = "Delivered! The receiving application gets the original data.";
  journeyBusy = false; $("journeyBtn").disabled = false;
}

/* ---------- TCP lifecycle ---------- */
const HS = {
  open: [
    ["right", "1. SYN (seq = x) - Client: I want to connect"],
    ["left",  "2. SYN-ACK (seq = y, ack = x+1) - Server: OK, I am ready too"],
    ["right", "3. ACK (ack = y+1) - Client: Confirmed"],
    ["ok",    "Connection ESTABLISHED - data can now flow"],
  ],
  close: [
    ["right", "1. FIN - Client: I have no more data to send"],
    ["left",  "2. ACK - Server: I got your FIN"],
    ["left",  "3. FIN - Server: I am finished too"],
    ["right", "4. ACK - Client: Goodbye (waits in TIME_WAIT)"],
    ["ok",    "Connection CLOSED"],
  ],
};
let hsMode = "open", hsIndex = 0;
function hsReset() { hsIndex = 0; $("hsSteps").innerHTML = ""; }
function hsNext() {
  const steps = HS[hsMode];
  if (hsIndex >= steps.length) return;
  const m = document.createElement("div");
  m.className = "msg " + steps[hsIndex][0];
  m.textContent = steps[hsIndex][1];
  $("hsSteps").appendChild(m);
  hsIndex++;
}
function hsTab(mode) {
  hsMode = mode;
  $("tabOpen").classList.toggle("active", mode === "open");
  $("tabClose").classList.toggle("active", mode === "close");
  hsReset();
}

/* ---------- Encapsulation ---------- */
function renderEncap() {
  const text = $("msg").value || "(empty)";
  $("encap").innerHTML = `
    <div class="box" style="--c:#f472b6"><b>NETWORK ACCESS - Ethernet frame</b>
      <span class="hdr">Dst MAC AA:BB:CC:11:22:33</span><span class="hdr">Src MAC 00:1A:2B:3C:4D:5E</span><span class="hdr">Type 0x0800</span>
      <div class="box" style="--c:#fbbf24"><b>INTERNET - IP packet</b>
        <span class="hdr">Src 192.168.1.10</span><span class="hdr">Dst 93.184.216.34</span><span class="hdr">TTL 64</span><span class="hdr">Proto 6 (TCP)</span>
        <div class="box" style="--c:#34d399"><b>TRANSPORT - TCP segment</b>
          <span class="hdr">Src port 51544</span><span class="hdr">Dst port 80</span><span class="hdr">Seq 1001</span><span class="hdr">Flags PSH,ACK</span>
          <div class="box" style="--c:#38bdf8"><b>APPLICATION - Data (${text.length} bytes)</b>
            <span class="data">${esc(text)}</span>
          </div>
        </div>
      </div>
      <span class="hdr">FCS (CRC)</span>
    </div>`;
}

/* ---------- Tools ---------- */
$("subBtn").onclick = () => runTool($("subOut"), async () =>
  kv(await api(`/api/subnet?ip=${encodeURIComponent($("subIp").value)}&prefix=${encodeURIComponent($("subPrefix").value)}`)));
$("dnsBtn").onclick = () => runTool($("dnsOut"), async () =>
  kv(await api(`/api/dns?host=${encodeURIComponent($("dnsHost").value)}`)));
$("portBtn").onclick = () => runTool($("portOut"), async () =>
  kv(await api(`/api/port?n=${encodeURIComponent($("portNum").value)}`)));
$("hdrBtn").onclick = () => runTool($("hdrOut"), async () => kv(await api("/api/headers")));

/* ---------- Ping chart ---------- */
let pingTimer = null, rtts = [];
async function pingOnce() {
  const t0 = performance.now();
  try { await fetch("/api/ping?" + Math.random()); } catch (e) { return; }
  rtts.push(performance.now() - t0);
  if (rtts.length > 40) rtts.shift();
  drawPing();
}
function drawPing() {
  const c = $("pingCanvas"), g = c.getContext("2d");
  const css = getComputedStyle(document.documentElement);
  g.clearRect(0, 0, c.width, c.height);
  if (!rtts.length) return;
  const max = Math.max(...rtts, 1) * 1.2, w = c.width, h = c.height;
  g.strokeStyle = css.getPropertyValue("--line"); g.lineWidth = 1;
  for (let i = 1; i < 4; i++) { g.beginPath(); g.moveTo(0, h * i / 4); g.lineTo(w, h * i / 4); g.stroke(); }
  g.strokeStyle = css.getPropertyValue("--accent"); g.lineWidth = 2.5; g.beginPath();
  rtts.forEach((v, i) => {
    const x = (i / 39) * w, y = h - (v / max) * h;
    i ? g.lineTo(x, y) : g.moveTo(x, y);
  });
  g.stroke();
  const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
  $("pingStat").textContent = ` last ${rtts.at(-1).toFixed(1)} ms | avg ${avg.toFixed(1)} ms | min ${Math.min(...rtts).toFixed(1)} ms | max ${Math.max(...rtts).toFixed(1)} ms`;
}
$("pingBtn").onclick = () => {
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; $("pingBtn").textContent = "Start"; return; }
  rtts = []; pingOnce(); pingTimer = setInterval(pingOnce, 500); $("pingBtn").textContent = "Stop";
};

/* ---------- Quiz (answers are checked by the server) ---------- */
let quiz = [], qi = 0, score = 0;
async function loadQuiz() { quiz = await api("/api/quiz"); qi = 0; score = 0; showQ(); }
function showQ() {
  const box = $("quizBox");
  if (qi >= quiz.length) {
    box.innerHTML = `<h3>Your score: ${score} / ${quiz.length}</h3><button id="qAgain">Try again</button>`;
    $("qAgain").onclick = loadQuiz; return;
  }
  const q = quiz[qi];
  box.innerHTML = `<p class="muted">Question ${qi + 1} of ${quiz.length}</p><h3>${esc(q.q)}</h3>` +
    q.options.map((o, i) => `<button class="opt" data-i="${i}">${esc(o)}</button>`).join("") + '<div id="qFb"></div>';
  box.querySelectorAll(".opt").forEach(b => b.onclick = async () => {
    const r = await api(`/api/quiz/check?id=${q.id}&choice=${b.dataset.i}`);
    box.querySelectorAll(".opt").forEach(x => { x.disabled = true; if (+x.dataset.i === r.answer) x.classList.add("right"); });
    if (r.correct) score++; else b.classList.add("wrong");
    $("qFb").innerHTML = `<p>${r.correct ? "Correct!" : "Not quite."} ${esc(r.explain)}</p>
      <button id="qNext">${qi + 1 < quiz.length ? "Next question" : "See score"}</button>`;
    $("qNext").onclick = () => { qi++; showQ(); };
  });
}

/* ---------- Live stats and log ---------- */
async function refresh() {
  try {
    const s = await api("/api/stats");
    $("reqs").textContent = s.requests;
    const t = s.uptime_seconds;
    $("uptime").textContent = t >= 60 ? `${Math.floor(t / 60)}m ${t % 60}s` : `${t}s`;
    const log = await api("/api/log");
    $("logBody").innerHTML = log.map(r =>
      `<tr><td>${esc(r.time)}</td><td>${esc(r.client)}</td><td>${esc(r.method)}</td><td>${esc(r.path)}</td><td>${esc(r.status)}</td></tr>`).join("");
  } catch (e) { /* server stopped */ }
}

/* ---------- Init ---------- */
async function init() {
  const info = await api("/api/info");
  $("reg").textContent = info.reg_no;
  $("name").textContent = info.name;
  protocols = await api("/api/protocols");
  $("count").textContent = protocols.length;
  renderFilters(); renderCards(); renderEncap(); hsTab("open");
  loadQuiz(); refresh();
  setInterval(refresh, 3000);
}

$("search").addEventListener("input", renderCards);
$("msg").addEventListener("input", renderEncap);
$("hsBtn").onclick = hsNext;
$("hsReset").onclick = hsReset;
$("tabOpen").onclick = () => hsTab("open");
$("tabClose").onclick = () => hsTab("close");
$("journeyBtn").onclick = journey;
document.addEventListener("keydown", e => {
  if (e.key === "/" && document.activeElement.tagName !== "INPUT") { e.preventDefault(); $("search").focus(); }
});
init();
