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
  frag.appendChild(makeWhois(data.whois, data.parsed.hostname));
  frag.appendChild(makeCert(data.cert, data.parsed.protocol));
  frag.appendChild(makeHeaders(data.headers));

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

function makeWhois(whois, hostname) {
  const section = el("div", "whois-section");

  const hdr = el("div", "section-header");
  hdr.textContent = "whois / registration";
  section.appendChild(hdr);

  if (!whois) {
    const skip = el("div", "whois-unavailable");
    skip.textContent = "WHOIS lookup skipped (IP address or unsupported host).";
    section.appendChild(skip);
    return section;
  }

  if (whois.error) {
    const err = el("div", "whois-unavailable");
    err.textContent = "WHOIS data unavailable — registry did not respond or domain not found.";
    section.appendChild(err);
    return section;
  }

  const grid = el("div", "whois-grid");

  if (whois.domainAgeDays !== null && whois.domainAgeDays !== undefined) {
    const ageBadge = el("div", "whois-age-badge" + (whois.domainAgeDays < 90 ? " age-new" : whois.domainAgeDays < 365 ? " age-young" : " age-old"));
    const ageYears = (whois.domainAgeDays / 365).toFixed(1);
    ageBadge.textContent = whois.domainAgeDays < 365
      ? `${whois.domainAgeDays}d old`
      : `${ageYears}y old`;
    ageBadge.title = `Registered: ${whois.created}`;
    grid.appendChild(ageBadge);
  }

  const rows = [
    ["domain",     whois.domain],
    ["registrar",  whois.registrar],
    ["registrant", whois.registrant],
    ["country",    whois.country],
    ["created",    whois.created],
    ["updated",    whois.updated],
    ["expires",    whois.expires],
  ].filter(([, v]) => v);

  rows.forEach(([k, v]) => {
    const row = el("div", "whois-row");
    const key = el("span", "whois-key"); key.textContent = k;
    const val = el("span", "whois-val"); val.textContent = v;
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  });

  if (whois.nameservers && whois.nameservers.length) {
    const row = el("div", "whois-row whois-row-ns");
    const key = el("span", "whois-key"); key.textContent = "nameservers";
    const val = el("div", "whois-ns-list");
    whois.nameservers.forEach(ns => {
      const chip = el("span", "ns-chip");
      chip.textContent = ns;
      val.appendChild(chip);
    });
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  }

  if (whois.status && whois.status.length) {
    const row = el("div", "whois-row");
    const key = el("span", "whois-key"); key.textContent = "status";
    const val = el("span", "whois-val whois-status"); val.textContent = whois.status.join(", ");
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  }

  section.appendChild(grid);
  return section;
}

function makeCert(cert, protocol) {
  const section = el("div", "cert-section");

  const hdr = el("div", "section-header");
  hdr.textContent = "tls certificate";
  section.appendChild(hdr);

  if (protocol !== "https:") {
    const skip = el("div", "cert-unavailable");
    skip.textContent = "Certificate check skipped — URL does not use HTTPS.";
    section.appendChild(skip);
    return section;
  }

  if (!cert) {
    const skip = el("div", "cert-unavailable");
    skip.textContent = "Certificate check skipped.";
    section.appendChild(skip);
    return section;
  }

  if (cert.error) {
    const err = el("div", "cert-unavailable");
    err.textContent = "Certificate data unavailable — could not connect to host.";
    section.appendChild(err);
    return section;
  }

  const grid = el("div", "cert-grid");

  if (cert.isSelfSigned) {
    const badge = el("div", "cert-badge cert-badge-danger");
    badge.textContent = "self-signed";
    grid.appendChild(badge);
  } else if (!cert.hostnameMatches) {
    const badge = el("div", "cert-badge cert-badge-danger");
    badge.textContent = "hostname mismatch";
    grid.appendChild(badge);
  } else if (cert.isExpired) {
    const badge = el("div", "cert-badge cert-badge-danger");
    badge.textContent = "expired";
    grid.appendChild(badge);
  } else if (cert.isExpiringSoon) {
    const badge = el("div", "cert-badge cert-badge-warn");
    badge.textContent = `expires in ${cert.daysLeft}d`;
    grid.appendChild(badge);
  } else {
    const badge = el("div", "cert-badge cert-badge-ok");
    badge.textContent = "valid";
    grid.appendChild(badge);
  }

  const rows = [
    ["issuer",     cert.issuerOrg || cert.issuerCN],
    ["issued to",  cert.subjectCN],
    ["valid from", cert.validFrom],
    ["valid to",   cert.validTo],
  ].filter(([, v]) => v);

  rows.forEach(([k, v]) => {
    const row = el("div", "cert-row");
    const key = el("span", "cert-key"); key.textContent = k;
    const val = el("span", "cert-val"); val.textContent = v;
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  });

  if (cert.sans && cert.sans.length) {
    const row = el("div", "cert-row cert-row-sans");
    const key = el("span", "cert-key"); key.textContent = "covers";
    const val = el("div", "cert-sans-list");
    cert.sans.forEach(san => {
      const chip = el("span", "cert-san-chip");
      chip.textContent = san;
      val.appendChild(chip);
    });
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  }

  section.appendChild(grid);
  return section;
}

function makeHeaders(headers) {
  const section = el("div", "headers-section");

  const hdr = el("div", "section-header");
  hdr.textContent = "http headers / origin";
  section.appendChild(hdr);

  if (!headers) {
    const skip = el("div", "headers-unavailable");
    skip.textContent = "Headers probe skipped.";
    section.appendChild(skip);
    return section;
  }

  if (headers.error) {
    const err = el("div", "headers-unavailable");
    err.textContent = "Could not fetch headers — host unreachable or refused HEAD request.";
    section.appendChild(err);
    return section;
  }

  const grid = el("div", "headers-grid");

  if (headers.detected && headers.detected.length) {
    const badgeRow = el("div", "headers-badge-row");
    headers.detected.forEach(d => {
      const badge = el("span", `headers-platform-badge headers-kind-${d.kind}`);
      badge.textContent = d.platform;
      badge.title = `detected via: ${d.header}`;
      badgeRow.appendChild(badge);
    });
    grid.appendChild(badgeRow);
  }

  const rows = [
    ["status",       headers.statusCode ? String(headers.statusCode) : null],
    ["server",       headers.serverDisplay || headers.serverRaw || null],
    ["powered by",   headers.poweredByDisplay || headers.poweredByRaw || null],
    ["content-type", headers.contentType || null],
  ].filter(([, v]) => v);

  rows.forEach(([k, v]) => {
    const row = el("div", "headers-row");
    const key = el("span", "headers-key"); key.textContent = k;
    const val = el("span", "headers-val"); val.textContent = v;
    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  });

  if (headers.exposed && headers.exposed.length) {
    const details = el("details", "headers-raw-details");
    const summary = el("summary", "headers-raw-summary");
    summary.textContent = `${headers.exposed.length} revealing header${headers.exposed.length > 1 ? "s" : ""} captured`;
    details.appendChild(summary);

    const table = el("div", "headers-raw-table");
    headers.exposed.forEach(({ name, value }) => {
      const row = el("div", "headers-raw-row");
      const k = el("span", "headers-raw-key"); k.textContent = name;
      const v = el("span", "headers-raw-val"); v.textContent = value;
      row.appendChild(k);
      row.appendChild(v);
      table.appendChild(row);
    });
    details.appendChild(table);
    grid.appendChild(details);
  }

  if (!rows.length && !(headers.detected && headers.detected.length)) {
    const none = el("div", "headers-unavailable");
    none.textContent = "No identifying headers returned by this server.";
    grid.appendChild(none);
  }

  section.appendChild(grid);
  return section;
}

function setLoading(on) {
  btn.disabled    = on;
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
