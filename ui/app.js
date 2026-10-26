"use strict";

const invoke = window.__TAURI__?.core?.invoke ?? (async (cmd) => { throw new Error(`Tauri недоступен (${cmd})`); });
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

let data = null;          // { settings, subscriptions, selected }
let status = null;
let pings = {};           // id сервера → мс (0 — нет ответа, -1 — UDP)
let activeSub = null;     // открытая вкладка подписки
let lastTraffic = null;   // { up, down, t }
let view = "home";

// ---------------------------------------------------------------------------
// утилиты
// ---------------------------------------------------------------------------

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function bytes(n) {
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i ? 1 : 0)} ${u[i]}`;
}

function duration(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor(sec / 60) % 60, s = sec % 60;
  return [h, m, s].map((v) => String(v).padStart(2, "0")).join(":");
}

let toastTimer;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.toggle("err", isErr);
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), isErr ? 6000 : 2600);
}

async function call(cmd, args, okMsg) {
  try {
    const r = await invoke(cmd, args);
    if (okMsg) toast(okMsg);
    return r;
  } catch (e) {
    toast(String(e), true);
    throw e;
  }
}

async function reload() {
  data = await invoke("get_state");
  if (!activeSub || !data.subscriptions.some((s) => s.id === activeSub)) {
    activeSub = selectedSubId() ?? data.subscriptions[0]?.id ?? null;
  }
  render();
}

function needsXray() {
  const sub = data?.subscriptions.find((s) => s.id === selectedSubId());
  return !!sub?.servers.some((x) => x.xray && !x.outbound);
}

function selectedSubId() {
  const sel = data?.selected;
  if (!sel) return null;
  if (sel.startsWith("auto:")) return sel.slice(5);
  return data.subscriptions.find((s) => s.servers.some((x) => x.id === sel))?.id ?? null;
}

// ---------------------------------------------------------------------------
// навигация
// ---------------------------------------------------------------------------

function show(v) {
  view = v;
  $$("nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  $$(".view").forEach((s) => s.classList.toggle("active", s.id === `view-${v}`));
  if (v === "logs") loadLogs();
  render();
}
$$("nav button").forEach((b) => (b.onclick = () => show(b.dataset.view)));
$("#current-server").onclick = () => show("servers");

// ---------------------------------------------------------------------------
// главный экран
// ---------------------------------------------------------------------------

const MODE_HINT = {
  tun: "Весь трафик компьютера идёт через виртуальный адаптер. Работает для любых программ, нужны права администратора.",
  proxy: "Windows направляет через VPN только программы, которые используют системный прокси (браузеры, большинство приложений).",
};

function renderHome() {
  const on = !!status?.running;
  const busy = !!status?.busy;
  document.body.classList.toggle("on", on);
  document.body.classList.toggle("busy", busy);
  $("#power").setAttribute("aria-label", on ? "Отключить" : "Подключить");
  $("#state-title").textContent = busy ? "Подключение…" : on ? "Подключено" : "Не подключено";
  const sub = $("#state-sub");
  sub.classList.remove("error");
  if (!status?.core_found) {
    sub.textContent = "Не найдено ядро sing-box. Переустановите приложение или положите sing-box.exe в папку core.";
    sub.classList.add("error");
  } else if (!status?.xray_found && needsXray()) {
    sub.textContent = "Для XHTTP-серверов нужно ядро Xray: положите xray.exe в папку core рядом с sing-box.exe.";
    sub.classList.add("error");
  } else if (status?.last_error && !on) {
    sub.textContent = status.last_error;
    sub.classList.add("error");
  } else if (on) {
    sub.textContent = status.mode === "tun" ? "Режим TUN" : `Системный прокси 127.0.0.1:${status.mixed_port}`;
  } else {
    sub.textContent = "Нажмите на тоннель, чтобы подключиться";
  }
  $("#stats").hidden = !on;
  $("#current-name").textContent = status?.selected_name ?? "Не выбран — добавьте подписку";
  const mode = data?.settings.mode ?? "tun";
  $$(".seg button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#mode-hint").textContent = MODE_HINT[mode];
  const foot = $("#side-status");
  foot.textContent = on ? `Подключено · ${status.selected_name ?? ""}` : "Не подключено";
  foot.classList.toggle("on", on);
}

$("#power").onclick = async () => {
  if (status?.busy) return;
  if (status?.running) {
    status = await call("disconnect");
  } else {
    if (!data?.selected) { show("servers"); return toast("Сначала добавьте подписку и выберите сервер", true); }
    status = { ...(status ?? {}), busy: true };
    renderHome();
    try { status = await call("connect"); } catch { status = await invoke("status"); }
  }
  renderHome();
};

$$(".seg button").forEach((b) => (b.onclick = async () => {
  if (data.settings.mode === b.dataset.mode) return;
  const settings = { ...data.settings, mode: b.dataset.mode };
  await call("save_settings", { settings }, status?.running ? "Режим изменён, подключение перезапущено" : "Режим изменён");
  await reload();
}));

async function poll() {
  try {
    status = await invoke("status");
    if (status.running) {
      $("#uptime").textContent = duration(Math.max(0, Math.floor(Date.now() / 1000) - status.started_at));
      const tr = await invoke("traffic");
      if (tr) {
        const t = performance.now();
        if (lastTraffic) {
          const dt = (t - lastTraffic.t) / 1000;
          $("#down").textContent = `${bytes(Math.max(0, tr.down - lastTraffic.down) / dt)}/с`;
          $("#up").textContent = `${bytes(Math.max(0, tr.up - lastTraffic.up) / dt)}/с`;
        }
        lastTraffic = { ...tr, t };
      }
    } else {
      lastTraffic = null;
    }
    if (view === "home") renderHome(); else renderSideOnly();
    if (view === "logs") loadLogs();
  } catch { /* окно в фоне */ }
}

function renderSideOnly() {
  const foot = $("#side-status");
  const on = !!status?.running;
  foot.textContent = on ? `Подключено · ${status.selected_name ?? ""}` : "Не подключено";
  foot.classList.toggle("on", on);
  document.body.classList.toggle("on", on);
}

// ---------------------------------------------------------------------------
// серверы и подписки
// ---------------------------------------------------------------------------

function pingCell(s) {
  if (s.id in pings) {
    const v = pings[s.id];
    if (v === -1) return `<span class="ping">UDP</span>`;
    if (!v) return `<span class="ping bad">нет ответа</span>`;
    const cls = v < 200 ? "good" : v < 500 ? "mid" : "bad";
    return `<span class="ping ${cls}">${v} мс</span>`;
  }
  return `<span class="ping"></span>`;
}

function renderServers() {
  const subs = data.subscriptions;
  $("#sub-tabs").innerHTML = subs
    .map((s) => `<button data-sub="${esc(s.id)}" class="${s.id === activeSub ? "active" : ""}">${esc(s.name)} <span class="muted">${s.servers.length}</span></button>`)
    .join("");
  $$("#sub-tabs button").forEach((b) => (b.onclick = () => { activeSub = b.dataset.sub; renderServers(); }));

  const sub = subs.find((s) => s.id === activeSub);
  if (!sub) {
    $("#sub-card").innerHTML = "";
    $("#server-list").innerHTML = `<div class="empty">Добавьте ссылку на подписку из бота или личного кабинета вашего VPN — серверы появятся здесь.</div>`;
    return;
  }

  // карточка подписки
  const info = sub.info;
  const meta = [];
  if (info) {
    const used = info.upload + info.download;
    meta.push(info.total ? `${bytes(used)} из ${bytes(info.total)}` : `${bytes(used)} использовано, безлимит`);
    if (info.expire) {
      const d = new Date(info.expire * 1000);
      const days = Math.ceil((info.expire * 1000 - Date.now()) / 86400000);
      meta.push(days >= 0 ? `до ${d.toLocaleDateString("ru-RU")} (${days} дн.)` : `истекла ${d.toLocaleDateString("ru-RU")}`);
    } else meta.push("бессрочно");
  }
  if (sub.url && sub.updated_at) meta.push(`обновлена ${new Date(sub.updated_at * 1000).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" })}`);
  const pct = info?.total ? Math.min(100, ((info.upload + info.download) / info.total) * 100) : null;
  const links = [
    sub.support_url && `<button class="icon" data-open="${esc(sub.support_url)}">Поддержка</button>`,
    sub.web_page_url && `<button class="icon" data-open="${esc(sub.web_page_url)}">Сайт</button>`,
  ].filter(Boolean).join("");
  $("#sub-card").innerHTML = `
    <div class="sub-card">
      <div class="meta">${meta.map(esc).map((m) => `<span>${m}</span>`).join("")}</div>
      <div class="sub-actions">
        ${links}
        <button class="ghost" id="ping-btn">Проверить пинг</button>
        ${sub.url ? `<button class="ghost" id="upd-btn">Обновить</button>` : ""}
        <button class="ghost" id="ren-btn">Переименовать</button>
        <button class="ghost" id="del-btn">Удалить</button>
      </div>
      ${pct !== null ? `<div class="usage"><i class="${pct > 85 ? "high" : ""}" style="width:${pct}%"></i></div>` : ""}
      ${sub.announce ? `<div class="announce">${esc(sub.announce)}</div>` : ""}
      ${sub.last_error ? `<div class="err">Последнее обновление не удалось: ${esc(sub.last_error)}</div>` : ""}
    </div>`;
  $$("[data-open]").forEach((b) => (b.onclick = () => call("open_url", { url: b.dataset.open })));
  $("#ping-btn").onclick = () => runPing(sub.id);
  if ($("#upd-btn")) $("#upd-btn").onclick = async (e) => {
    e.target.disabled = true;
    try { await call("update_subscription", { id: sub.id }, "Подписка обновлена"); } finally { await reload(); }
  };
  $("#ren-btn").onclick = async () => {
    const name = prompt("Новое название", sub.name);
    if (name?.trim()) { await call("rename_subscription", { id: sub.id, name }); await reload(); }
  };
  $("#del-btn").onclick = async () => {
    if (!confirm(`Удалить «${sub.name}»?`)) return;
    await call("remove_subscription", { id: sub.id }, "Удалено");
    activeSub = null;
    await reload();
  };

  // список серверов
  const autoId = `auto:${sub.id}`;
  const usable = sub.servers.filter((s) => s.outbound || s.xray);
  const rows = [];
  if (usable.length > 1) {
    rows.push(`
      <div class="srv ${data.selected === autoId ? "sel" : ""}" data-id="${esc(autoId)}">
        <span class="dot"></span>
        <span class="name">Автовыбор<small>лучший сервер по задержке, переключается сам</small></span>
        <span class="proto"></span><span class="ping"></span><span></span>
      </div>`);
  }
  for (const s of sub.servers) {
    const ok = !!(s.outbound || s.xray);
    rows.push(`
      <div class="srv ${ok ? "" : "disabled"} ${data.selected === s.id ? "sel" : ""}" data-id="${esc(s.id)}" ${ok ? "" : `title="${esc(s.error)}"`}>
        <span class="dot"></span>
        <span class="name">${esc(s.name)}${ok ? "" : `<small>${esc(s.error)}</small>`}</span>
        <span class="proto">${esc(s.protocol)}${s.transport ? ` · ${esc(s.transport)}` : ""}${s.xray && !s.outbound ? ` <b class="xr" title="Работает через ядро Xray">Xray</b>` : ""}</span>
        ${ok ? pingCell(s) : `<span class="ping"></span>`}
        ${sub.id === "manual" ? `<button class="icon" data-del="${esc(s.id)}" title="Удалить сервер">✕</button>` : "<span></span>"}
      </div>`);
  }
  $("#server-list").innerHTML = rows.join("") || `<div class="empty">В подписке нет серверов</div>`;
  $$("#server-list .srv:not(.disabled)").forEach((r) => (r.onclick = async (e) => {
    if (e.target.closest("[data-del]")) return;
    status = await call("select_server", { id: r.dataset.id });
    await reload();
  }));
  $$("[data-del]").forEach((b) => (b.onclick = async () => { await call("remove_server", { id: b.dataset.del }); await reload(); }));
}

async function runPing(subId) {
  const btn = $("#ping-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Проверяю…"; }
  try {
    Object.assign(pings, await call("ping", { subId }));
  } finally {
    if (view === "servers") renderServers();
  }
}

$("#add-btn").onclick = async () => {
  const input = $("#add-input").value.trim();
  if (!input) return toast("Вставьте ссылку", true);
  const btn = $("#add-btn");
  btn.disabled = true;
  btn.textContent = "Загружаю…";
  try {
    activeSub = await call("add_subscription", { input }, "Добавлено");
    $("#add-input").value = "";
  } finally {
    btn.disabled = false;
    btn.textContent = "Добавить";
    await reload();
  }
};

$("#paste-btn").onclick = async () => {
  try {
    $("#add-input").value = await navigator.clipboard.readText();
    $("#add-btn").click();
  } catch {
    toast("Не удалось прочитать буфер обмена — вставьте ссылку вручную (Ctrl+V)", true);
  }
};

$("#update-all").onclick = async (e) => {
  e.target.disabled = true;
  try {
    const errors = await call("update_all");
    toast(errors.length ? `Обновлено с ошибками: ${errors.join("; ")}` : "Все подписки обновлены", errors.length > 0);
  } finally {
    e.target.disabled = false;
    await reload();
  }
};

// ---------------------------------------------------------------------------
// раздельное туннелирование
// ---------------------------------------------------------------------------

let splitDraft = null;

function renderSplit() {
  if (!splitDraft) splitDraft = structuredClone(data.settings.split);
  $$("#app-mode input").forEach((i) => (i.checked = i.value === splitDraft.app_mode));
  $("#apps").innerHTML = splitDraft.apps
    .map((a, i) => `<span class="chip">${esc(a)}<button data-i="${i}" aria-label="Убрать">×</button></span>`)
    .join("") || `<span class="muted">Приложения не выбраны</span>`;
  $$("#apps button").forEach((b) => (b.onclick = () => { splitDraft.apps.splice(+b.dataset.i, 1); renderSplit(); }));
  if (document.activeElement !== $("#proxy-domains")) $("#proxy-domains").value = splitDraft.proxy_domains.join("\n");
  if (document.activeElement !== $("#direct-domains")) $("#direct-domains").value = splitDraft.direct_domains.join("\n");
  $("#ru-direct").checked = splitDraft.ru_direct;
}

$$("#app-mode input").forEach((i) => (i.onchange = () => (splitDraft.app_mode = i.value)));
$("#ru-direct").onchange = (e) => (splitDraft.ru_direct = e.target.checked);
const lines = (s) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
$("#proxy-domains").oninput = (e) => (splitDraft.proxy_domains = lines(e.target.value));
$("#direct-domains").oninput = (e) => (splitDraft.direct_domains = lines(e.target.value));

function addApp(name) {
  name = name.trim();
  if (name && !splitDraft.apps.some((a) => a.toLowerCase() === name.toLowerCase())) splitDraft.apps.push(name);
}
$("#app-add").onclick = () => { addApp($("#app-input").value); $("#app-input").value = ""; renderSplit(); };
$("#app-input").onkeydown = (e) => { if (e.key === "Enter") $("#app-add").click(); };

let procs = [];
function renderProcs() {
  const f = $("#proc-filter").value.toLowerCase();
  const chosen = new Set(splitDraft.apps.map((a) => a.toLowerCase()));
  $("#proc-list").innerHTML = procs
    .filter((p) => !f || p.name.toLowerCase().includes(f) || (p.path ?? "").toLowerCase().includes(f))
    .map((p) => `<label><input type="checkbox" value="${esc(p.name)}" ${chosen.has(p.name.toLowerCase()) ? "checked" : ""} />${esc(p.name)}<small>${esc(p.path ?? "")}</small></label>`)
    .join("") || `<div class="empty">Ничего не найдено</div>`;
  $$("#proc-list input").forEach((i) => (i.onchange = () => {
    if (i.checked) addApp(i.value);
    else splitDraft.apps = splitDraft.apps.filter((a) => a.toLowerCase() !== i.value.toLowerCase());
    renderSplit();
  }));
}
$("#app-pick").onclick = async () => {
  procs = await call("list_processes");
  $("#proc-filter").value = "";
  renderProcs();
  $("#proc-dialog").showModal();
};
$("#proc-filter").oninput = renderProcs;

$("#split-save").onclick = async () => {
  if (splitDraft.app_mode !== "off" && !splitDraft.apps.length) {
    return toast("Добавьте хотя бы одно приложение или выберите «Не разделять по приложениям»", true);
  }
  const settings = { ...data.settings, split: splitDraft };
  await call("save_settings", { settings }, status?.running ? "Сохранено, подключение перезапущено" : "Сохранено");
  splitDraft = null;
  await reload();
};

// ---------------------------------------------------------------------------
// настройки
// ---------------------------------------------------------------------------

const FIELDS = [
  ["#s-dns-remote", "dns_remote"], ["#s-dns-direct", "dns_direct"], ["#s-ua", "user_agent"], ["#s-log", "log_level"],
  ["#s-core", "core"], ["#s-xray-port", "xray_port", Number],
  ["#s-mixed", "mixed_port", Number], ["#s-ext", "ext_port", Number], ["#s-api", "api_port", Number], ["#s-clash", "clash_port", Number],
];
const CHECKS = [["#s-ipv6", "ipv6"], ["#s-lan", "allow_lan"], ["#s-auto", "auto_connect"]];

function renderSettings() {
  const s = data.settings;
  for (const [sel, key] of FIELDS) if (document.activeElement !== $(sel)) $(sel).value = s[key];
  for (const [sel, key] of CHECKS) $(sel).checked = s[key];
  $("#pair-port").textContent = s.api_port;
  $("#pair-token").textContent = s.api_token;
}

$("#settings-save").onclick = async () => {
  const s = { ...data.settings };
  for (const [sel, key, conv] of FIELDS) s[key] = conv ? conv($(sel).value) : $(sel).value.trim();
  for (const [sel, key] of CHECKS) s[key] = $(sel).checked;
  await call("save_settings", { settings: s }, "Настройки сохранены");
  await reload();
};
$("#copy-token").onclick = async () => {
  try { await navigator.clipboard.writeText(data.settings.api_token); toast("Токен скопирован"); }
  catch { toast("Выделите токен и нажмите Ctrl+C", true); }
};
$("#new-token").onclick = async () => {
  if (!confirm("Старый токен перестанет работать в расширении. Продолжить?")) return;
  await call("regenerate_token", undefined, "Создан новый токен");
  await reload();
};

// ---------------------------------------------------------------------------
// журнал
// ---------------------------------------------------------------------------

async function loadLogs() {
  const box = $("#log-box");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  const l = await invoke("logs");
  box.textContent = l.join("\n") || "Журнал пуст. Здесь появятся сообщения ядра после подключения.";
  if (atBottom) box.scrollTop = box.scrollHeight;
}
$("#logs-clear").onclick = async () => { await invoke("clear_logs"); loadLogs(); };

// ---------------------------------------------------------------------------

function render() {
  if (!data) return;
  if (view === "home") renderHome();
  if (view === "servers") renderServers();
  if (view === "split") renderSplit();
  if (view === "settings") renderSettings();
  renderSideOnly();
}

(async () => {
  try {
    status = await invoke("status");
    await reload();
  } catch (e) {
    toast(String(e), true);
  }
  setInterval(poll, 1000);
})();
