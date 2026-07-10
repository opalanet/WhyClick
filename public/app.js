const input  = document.getElementById("urlInput");
const btn    = document.getElementById("analyzeBtn");
const output = document.getElementById("output");

btn.addEventListener("click", run);

input.addEventListener("keydown", e => {
  if (e.key === "Enter") run();
});

async function run() {
  const raw = input.value.trim();
  if (!raw) { input.focus(); return; }

  setLoading(true);
  output.innerHTML = "";

  try {
    const res  = await fetch("/api/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: raw }),
    });

    const data = await res.json();
    render(data);
  } catch (err) {
    renderError("Could not reach the server. Is it running?");
  } finally {
    setLoading(false);
  }
}

function render(data) {
  if (data.error) {
    renderError(data.message);
    return;
  }

  const frag = document.createDocumentFragment();

  frag.appendChild(makeVerdictBar(data));

  frag.appendChild(makeBreakdown(data.parsed));

  frag.appendChild(makeFindings(data.findings));

  output.appendChild(frag);

  typewrite(document.querySelector(".verdict-label"), data.verdict);
}

function renderError(msg) {
  output.innerHTML = `<div class="error-block">${escHtml(msg)}</div>`;
}

function makeVerdictBar(data) {
  const bar = el("div", `verdict-bar ${data.verdictCode}`);

  const label = el("div", "verdict-label");
  label.textContent = "";
  label.dataset.target = data.verdict;

  const pill = el("div", "score-pill");
  pill.textContent = `risk score: ${data.riskScore}/100`;

  bar.appendChild(label);
  bar.appendChild(pill);
  return bar;
}

function makeBreakdown(parsed) {
  const wrap = el("div", "url-breakdown");

  const lbl = el("div", "section-label");
  lbl.textContent = "URL breakdown";
  wrap.appendChild(lbl);

  const rows = [
    ["protocol", parsed.protocol],
    ["host",     parsed.hostname],
    ["path",     parsed.pathname || "/"],
  ];

  const paramKeys = Object.keys(parsed.params);
  if (paramKeys.length) {
    rows.push(["params", paramKeys.map(k => `${k}=${parsed.params[k]}`).join("  ")]);
  }

  rows.forEach(([k, v]) => {
    const row = el("div", "url-row");
    const key = el("span", "url-key"); key.textContent = k;
    const val = el("span", "url-val"); val.textContent = v;
    row.appendChild(key);
    row.appendChild(val);
    wrap.appendChild(row);
  });

  return wrap;
}

function makeFindings(findings) {
  const wrap = document.createDocumentFragment();

  const hdr = el("div", "section-header");
  hdr.textContent = findings.length
    ? `findings (${findings.length})`
    : "findings";
  wrap.appendChild(hdr);

  if (!findings.length) {
    const none = el("div", "no-findings");
    none.textContent = "No suspicious patterns detected.";
    wrap.appendChild(none);
    return wrap;
  }

  const list = el("div", "findings");

  const order = { high: 0, medium: 1, low: 2 };
  [...findings].sort((a, b) => order[a.severity] - order[b.severity]).forEach(f => {
    const item = el("div", `finding ${f.severity}`);

    const sev  = el("div", "finding-severity");
    sev.textContent = f.severity;

    const body  = el("div", "finding-body");
    const label = el("div", "finding-label");
    label.textContent = f.label;
    const detail = el("div", "finding-detail");
    detail.textContent = f.detail;
    body.appendChild(label);
    body.appendChild(detail);

    item.appendChild(sev);
    item.appendChild(body);
    list.appendChild(item);
  });

  wrap.appendChild(list);
  return wrap;
}

function setLoading(on) {
  btn.disabled   = on;
  btn.textContent = on ? "analyzing..." : "analyze →";
}

function el(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function escHtml(str) {
  return str.replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function typewrite(elem, text, speed = 55) {
  let i = 0;
  const cursor = document.createElement("span");
  cursor.className = "cursor";
  elem.appendChild(cursor);

  const tick = () => {
    if (i < text.length) {
      cursor.insertAdjacentText("beforebegin", text[i++]);
      setTimeout(tick, speed);
    } else {
      cursor.remove();
    }
  };
  tick();
}
