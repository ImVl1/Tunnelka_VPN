"use strict";

const $ = (s) => document.querySelector(s);
let state = null;
let eff = null;

async function send(msg) {
  const r = await chrome.runtime.sendMessage(msg);
  if (!r?.ok) throw new Error(r?.error || "ошибка");
  return r.data;
}

function showError(text) {
  const e = $("#error");
  e.textContent = text || "";
  e.hidden = !text;
}

async function run(msg) {
  try {
    const r = await send(msg);
    if (r?.state) { state = r.state; eff = r.effective; }
    render();
    return r;
  } catch (e) {
    showError(e.message);
  }
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------------------------------------------------------------------------

function render() {
  if (!state) return;
  $("#enabled").checked = state.enabled;
  document.querySelectorAll(".seg button").forEach((b) => b.classList.toggle("active", b.dataset.mode === state.mode));
  $("#sec-app").hidden = state.mode !== "app";
  $("#sec-direct").hidden = state.mode !== "direct";

  const st = $("#status");
  st.classList.toggle("on", !!eff?.active);
  if (eff?.active) {
    st.textContent = state.mode === "app"
      ? `Через VPN · ${eff.appStatus?.selected_name ?? ""}`
      : `Через прокси · ${state.direct.servers.find((x) => x.id === state.direct.selected)?.name ?? ""}`;
  } else {
    st.textContent = state.enabled ? "Ожидание подключения" : "Браузер работает напрямую";
  }
  showError(eff?.error);

  // приложение
  const a = eff?.appStatus;
  $("#app-state").textContent = !a ? "Приложение недоступно" : a.running ? "VPN в приложении включён" : "VPN в приложении выключен";
  $("#app-toggle").textContent = a?.running ? "Отключить" : "Подключить";
  $("#app-toggle").disabled = !a;
  if (document.activeElement !== $("#app-port")) $("#app-port").value = state.app.port;
  if (document.activeElement !== $("#app-token")) $("#app-token").value = state.app.token;
  if (!state.app.token) $("#pair").open = true;

  // свой прокси
  $("#direct-list").innerHTML = state.direct.servers
    .map((s) => `<div class="item ${s.id === state.direct.selected ? "sel" : ""}" data-id="${esc(s.id)}">
        <span>${esc(s.name)}</span><small>${esc(s.scheme)}</small>
        <button data-del="${esc(s.id)}" title="Удалить">✕</button></div>`)
    .join("");
  document.querySelectorAll("#direct-list .item").forEach((el) => (el.onclick = (e) => {
    if (e.target.dataset.del) return;
    run({ type: "set", patch: { direct: { ...state.direct, selected: el.dataset.id } } });
  }));
  document.querySelectorAll("[data-del]").forEach((b) => (b.onclick = () => {
    const servers = state.direct.servers.filter((s) => s.id !== b.dataset.del);
    const selected = state.direct.selected === b.dataset.del ? servers[0]?.id ?? null : state.direct.selected;
    run({ type: "set", patch: { direct: { servers, selected } } });
  }));

  // маршрутизация
  $("#route-type").value = state.routing.type;
  $("#route-box").hidden = state.routing.type === "all";
  if (document.activeElement !== $("#domains")) $("#domains").value = state.routing.domains.join("\n");
  $("#webrtc").checked = state.webrtc;
}

async function loadAppServers() {
  const sel = $("#app-server");
  if (state.mode !== "app" || !eff?.appStatus) { sel.hidden = true; return; }
  try {
    const r = await send({ type: "appServers" });
    sel.innerHTML = r.subscriptions
      .filter((s) => s.servers.length)
      .map((s) => `<optgroup label="${esc(s.name)}">
          ${s.servers.length > 1 ? `<option value="auto:${esc(s.id)}">Автовыбор</option>` : ""}
          ${s.servers.map((x) => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("")}
        </optgroup>`)
      .join("");
    sel.value = r.selected ?? "";
    sel.hidden = !sel.options.length;
  } catch (e) {
    sel.hidden = true;
  }
}

// ---------------------------------------------------------------------------

$("#enabled").onchange = async (e) => {
  if (e.target.checked && state.mode === "app" && eff?.appStatus && !eff.appStatus.running) {
    await run({ type: "appConnect" });
  } else {
    await run({ type: "set", patch: { enabled: e.target.checked } });
  }
};

document.querySelectorAll(".seg button").forEach((b) => (b.onclick = async () => {
  await run({ type: "set", patch: { mode: b.dataset.mode } });
  loadAppServers();
}));

$("#app-toggle").onclick = async (e) => {
  e.target.disabled = true;
  e.target.textContent = "Подождите…";
  await run({ type: eff?.appStatus?.running ? "appDisconnect" : "appConnect" });
};

$("#app-server").onchange = (e) => run({ type: "appSelect", server: e.target.value });

$("#pair-save").onclick = async () => {
  const port = Number($("#app-port").value) || 2082;
  const token = $("#app-token").value.trim();
  await run({ type: "set", patch: { app: { port, token } } });
  if (eff?.appStatus) { $("#pair").open = false; loadAppServers(); }
};

// Разбор ссылок socks5://user:pass@host:port, http://, https://, socks4://
function parseProxy(line) {
  const m = line.trim().match(/^(socks5h?|socks4a?|socks|https?):\/\/(?:([^:@/]*)(?::([^@/]*))?@)?(\[[^\]]+\]|[^:/#?]+):(\d+)\/?(?:#(.*))?$/i);
  if (!m) return null;
  let scheme = m[1].toLowerCase();
  if (scheme.startsWith("socks5") || scheme === "socks") scheme = "socks5";
  if (scheme.startsWith("socks4")) scheme = "socks4";
  const host = m[4], port = Number(m[5]);
  if (!port || port > 65535) return null;
  const dec = (s) => (s ? decodeURIComponent(s) : "");
  return {
    id: `${scheme}://${host}:${port}`,
    name: m[6] ? dec(m[6]) : `${host}:${port}`,
    scheme, host, port,
    user: dec(m[2]), pass: dec(m[3]),
  };
}

$("#direct-add").onclick = async () => {
  const lines = $("#direct-input").value.split(/\r?\n/).filter((l) => l.trim());
  const parsed = lines.map(parseProxy);
  const bad = lines.filter((_, i) => !parsed[i]);
  const servers = [...state.direct.servers];
  for (const p of parsed.filter(Boolean)) {
    const i = servers.findIndex((s) => s.id === p.id);
    if (i >= 0) servers[i] = p; else servers.push(p);
  }
  const selected = state.direct.selected ?? servers[0]?.id ?? null;
  await run({ type: "set", patch: { direct: { servers, selected } } });
  $("#direct-input").value = bad.join("\n");
  if (bad.length) showError("Не удалось разобрать: " + bad.join(", ") + ". Формат: socks5://host:порт или http://логин:пароль@host:порт");
};

$("#route-type").onchange = (e) => run({ type: "set", patch: { routing: { ...state.routing, type: e.target.value } } });

const domainLines = () => [...new Set($("#domains").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))];
$("#domains-save").onclick = () => run({ type: "set", patch: { routing: { ...state.routing, domains: domainLines() } } });

$("#add-current").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host;
  try { host = new URL(tab.url).hostname.replace(/^www\./, ""); } catch { /* служебная страница */ }
  if (!host || !/^https?:/.test(tab.url)) return showError("Откройте обычный сайт, чтобы добавить его");
  const domains = [...new Set([...domainLines(), host])];
  await run({ type: "set", patch: { routing: { ...state.routing, domains } } });
};

$("#webrtc").onchange = (e) => run({ type: "set", patch: { webrtc: e.target.checked } });

(async () => {
  await run({ type: "get" });
  loadAppServers();
})();
