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
let platform = "windows";  // windows | android
const isAndroid = () => platform === "android";

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
  const version = settingsVersion;
  const state = await invoke("get_state");
  if (version !== settingsVersion) state.settings = data.settings;
  data = state;
  if (!activeSub || !data.subscriptions.some((s) => s.id === activeSub)) {
    activeSub = selectedSubId() ?? data.subscriptions[0]?.id ?? null;
  }
  render();
}

function openUrl(url) {
  if (!/^(https?|tg):\/\//.test(url)) return;
  // Ссылки всегда открываются во внешнем браузере.
  call("open_url", { url });
}

function needsXray() {
  return !!data?.subscriptions.some((sub) => sub.servers.some((x) => x.xray && !x.outbound));
}

function selectedSubId() {
  const sel = data?.selected;
  if (!sel || sel === "auto+") return null;
  if (sel.startsWith("auto:")) return sel.slice(5);
  return data.subscriptions.find((s) => s.servers.some((x) => x.id === sel))?.id ?? null;
}

// ---------------------------------------------------------------------------
// навигация
// ---------------------------------------------------------------------------

function show(v) {
  if (v !== view) {
    flushSettings();
    $("main").scrollTop = 0;
  }
  view = v;
  $$("nav button").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === v);
    if (b.dataset.view === v) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
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
  const paused = !!status?.paused;
  document.body.classList.toggle("on", on && !paused);
  document.body.classList.toggle("busy", busy);
  document.body.classList.toggle("paused", paused);
  $("#power").setAttribute("aria-label", on && !paused ? "Отключить" : "Подключить");
  $("#state-title").textContent = busy ? "Подключение…" : paused ? "Пауза" : on ? "Подключено" : "Не подключено";
  $("#state-pill-text").textContent = busy ? "Подключение" : paused ? "VPN на паузе"
    : on ? (status.checking ? "Проверяю соединение…" : "Защищено") : "Не подключено";
  const sub = $("#state-sub");
  sub.classList.remove("error");
  if (!status?.core_found) {
    sub.textContent = "Не найдено ядро sing-box. Переустановите приложение.";
    sub.classList.add("error");
  } else if (!status?.xray_found && needsXray()) {
    sub.textContent = "Для XHTTP-серверов нужно ядро Xray. Переустановите приложение.";
    sub.classList.add("error");
  } else if (status?.last_error && !on && !busy) {
    sub.textContent = status.last_error;
    sub.classList.add("error");
  } else if (!on && !busy && status?.kill_switch_active) {
    sub.textContent = "Интернет заблокирован kill switch. Подключитесь или нажмите «Разблокировать интернет»";
    sub.classList.add("error");
  } else if (paused) {
    sub.textContent = "Трафик идёт напрямую. Нажмите на тоннель, чтобы продолжить";
  } else if (on) {
    sub.textContent = isAndroid() ? "Трафик телефона идёт через VPN"
      : status.mode === "tun" ? "Весь трафик компьютера идёт через VPN" : `Системный прокси 127.0.0.1:${status.mixed_port}`;
  } else if (busy) {
    sub.textContent = "Запускаю ядро и проверяю сервер";
  } else {
    sub.textContent = "Нажмите на тоннель, чтобы подключиться";
  }
  $("#stats").hidden = !on || paused;
  const exit = $("#exit-info");
  exit.hidden = !(on && !paused && status?.exit_ip);
  exit.textContent = status?.exit_ip ? `${status.exit_ip}${status.exit_place ? ` · ${status.exit_place}` : ""}` : "";
  const notice = $("#notice");
  notice.hidden = !(on && status?.notice);
  notice.textContent = status?.notice ?? "";
  $("#unblock").hidden = on || !status?.kill_switch_active;
  $("#current-name").textContent = status?.selected_name ?? "Не выбран — добавьте подписку";
  const mode = settingsEdits.mode ?? data?.settings.mode ?? "tun";
  $$("[data-mode]").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#mode-hint").textContent = MODE_HINT[mode];
  renderSideOnly();
}

$("#power").onclick = async () => {
  if (status?.busy) return;
  if (status?.running && !status?.paused) {
    status = await call("disconnect");
  } else {
    if (!data?.selected) { show("servers"); return toast("Сначала добавьте подписку и выберите сервер", true); }
    status = { ...(status ?? {}), busy: true };
    renderHome();
    try { status = await call("connect"); } catch { status = await invoke("status"); }
  }
  renderHome();
};

$("#unblock").onclick = async () => {
  status = await call("unblock", undefined, "Интернет разблокирован");
  renderHome();
};

$$("button[data-mode]").forEach(b => b.onclick = () => {
  editSetting("mode", b.dataset.mode);
  renderHome();
});

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
    if (view === "settings" && isAndroid() && ++batteryTick % 5 === 0) renderBattery();
    if (view === "logs") loadLogs();
  } catch { /* окно в фоне */ }
}

function renderSideOnly() {
  const foot = $("#side-status");
  const on = !!status?.running && !status?.paused;
  foot.querySelector("span").textContent = status?.paused ? "Пауза" : on ? `Подключено · ${status.selected_name ?? ""}` : "Не подключено";
  foot.classList.toggle("on", on);
  document.body.classList.toggle("on", on);
}

// ---------------------------------------------------------------------------
// серверы и подписки
// ---------------------------------------------------------------------------

function pingHtml(id) {
  if (id in pings) {
    const v = pings[id];
    if (v === -1) return { cls: "", text: "UDP" };
    if (!v) return { cls: "bad", text: "нет ответа" };
    return { cls: v < 200 ? "good" : v < 500 ? "mid" : "bad", text: `${v} мс` };
  }
  return { cls: "", text: pingBusy.has(id) ? "…" : "" };
}
function pingCell(s) {
  const p = pingHtml(s.id);
  return `<span class="ping ${p.cls}" data-ping="${esc(s.id)}">${esc(p.text)}</span>`;
}
/** Обновляет только ячейки пинга, не перерисовывая список. */
function paintPings() {
  $$("[data-ping]").forEach((el) => {
    const p = pingHtml(el.dataset.ping);
    el.className = `ping ${p.cls}`;
    el.textContent = p.text;
  });
}

const usableCount = () => data.subscriptions.filter((s) => s.servers.some((x) => x.outbound || x.xray)).length;

function matchingServers(sub, query) {
  const words = query.toLowerCase().trim().split(/\s+/);
  return sub.servers.filter(server => {
    const text = [sub.name, server.name, server.address, server.protocol, server.transport].join(" ").toLowerCase();
    return words.every(word => text.includes(word));
  });
}
$("#server-search").oninput = renderServers;

function renderServers() {
  const subs = data.subscriptions;
  const query = $("#server-search").value.trim();
  for (const id of ["#auto-all", "#sub-tabs", "#sub-card"]) $(id).hidden = !!query;
  // «Автовыбор+» — поверх всех подписок.
  $("#auto-all").innerHTML = usableCount() > 1 ? `
      <div class="srv plus ${data.selected === "auto+" ? "sel" : ""}" data-id="auto+">
        <span class="dot"></span>
        <span class="name"><b>Автовыбор+</b><small>лучший сервер из всех подписок</small></span>
        <span class="proto"></span><span class="ping"></span><span></span>
      </div>` : "";
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
  $("#sub-card").innerHTML = `
    <div class="sub-card">
      <div class="meta">${meta.map(esc).map((m) => `<span>${m}</span>`).join("")}</div>
      <div class="sub-actions">
        <button class="btn small" id="ping-btn" ${pingRunning ? "disabled" : ""}>${pingRunning ? "Проверяю…" : "Проверить пинг"}</button>
        ${sub.url ? `<button class="btn small" id="upd-btn">Обновить</button>` : ""}
        <button class="btn small" id="more-btn" aria-label="Ещё"><svg><use href="#i-more" /></svg>Ещё</button>
      </div>
      ${pct !== null ? `<div class="usage"><i class="${pct > 85 ? "high" : ""}" style="width:${pct}%"></i></div>` : ""}
      ${sub.announce ? `<div class="announce">${esc(sub.announce)}</div>` : ""}
      ${sub.last_error ? `<div class="err">Последнее обновление не удалось: ${esc(sub.last_error)}</div>` : ""}
    </div>`;
  $("#ping-btn").onclick = () => runPing(sub.id);
  if ($("#upd-btn")) $("#upd-btn").onclick = async (e) => {
    e.target.disabled = true;
    try { await call("update_subscription", { id: sub.id }, "Подписка обновлена"); } finally { await reload(); }
  };
  $("#more-btn").onclick = () => openSubMenu(sub);

  // список серверов
  const autoId = `auto:${sub.id}`;
  const usable = sub.servers.filter((s) => s.outbound || s.xray);
  const rows = [];
  if (!query && usable.length > 1) {
    rows.push(`
      <div class="srv ${data.selected === autoId ? "sel" : ""}" data-id="${esc(autoId)}">
        <span class="dot"></span>
        <span class="name">Автовыбор<small>лучший сервер этой подписки</small></span>
        <span class="proto"></span><span class="ping"></span><span></span>
      </div>`);
  }
  for (const group of query ? subs : [sub]) {
    const matches = query ? matchingServers(group, query) : group.servers;
    if (query && matches.length) rows.push(`<h3 class="result-heading">${esc(group.name)}</h3>`);
    for (const s of matches) {
      const ok = !!(s.outbound || s.xray);
      rows.push(`
        <div class="srv ${ok ? "" : "disabled"} ${data.selected === s.id ? "sel" : ""}" data-id="${esc(s.id)}" ${ok ? "" : `title="${esc(s.error)}"`}>
          <span class="dot"></span>
          <span class="name">${esc(s.name)}${ok ? "" : `<small>${esc(s.error)}</small>`}</span>
          <span class="proto">${esc(s.protocol)}${s.transport ? ` · ${esc(s.transport)}` : ""}${s.xray && !s.outbound ? ` <b class="xr" title="Работает через ядро Xray">Xray</b>` : ""}</span>
          ${ok ? pingCell(s) : `<span class="ping"></span>`}
          ${group.id === "manual" ? `<button class="icon" data-del="${esc(s.id)}" title="Удалить сервер">✕</button>` : "<span></span>"}
        </div>`);
    }
  }
  $("#server-list").innerHTML = rows.join("") || `<div class="empty">${query ? "Серверы не найдены" : "В подписке нет серверов"}</div>`;
  $$("#server-list .srv:not(.disabled), #auto-all .srv").forEach((r) => (r.onclick = async (e) => {
    if (e.target.closest("[data-del]")) return;
    status = await call("select_server", { id: r.dataset.id });
    await reload();
  }));
  $$("[data-del]").forEach((b) => (b.onclick = async () => { await call("remove_server", { id: b.dataset.del }); await reload(); }));
}

// Проверка пинга: результаты появляются по мере готовности.
let pingRunning = false;
let pingBusy = new Set();
async function runPing(subId) {
  if (pingRunning) return;
  pingRunning = true;
  const sub = data.subscriptions.find((s) => s.id === subId);
  pingBusy = new Set((sub?.servers ?? []).map((s) => s.id));
  for (const id of pingBusy) delete pings[id];
  if (view === "servers") renderServers();
  const timer = setInterval(async () => {
    try { Object.assign(pings, await invoke("ping_progress")); paintPings(); } catch { /* */ }
  }, 400);
  try {
    Object.assign(pings, await call("ping", { subId }));
  } finally {
    clearInterval(timer);
    pingRunning = false;
    pingBusy = new Set();
    if (view === "servers") renderServers();
  }
}

// ---- меню подписки ----

function shareLabel() { return isAndroid() ? "Поделиться ссылкой" : "Скопировать ссылку"; }

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return toast("Ссылка скопирована"); } catch { /* ниже — запасной способ */ }
  const t = document.createElement("textarea");
  t.value = text;
  document.body.append(t);
  t.select();
  const ok = document.execCommand("copy");
  t.remove();
  toast(ok ? "Ссылка скопирована" : "Не удалось скопировать ссылку", !ok);
}

async function shareLink(sub) {
  if (isAndroid()) {
    try { await invoke("share_text", { text: sub.url, title: sub.name }); return; } catch { /* ниже — копирование */ }
  }
  copyText(sub.url);
}

function showQr(sub) {
  try {
    const q = qrcode(0, "M");
    q.addData(sub.url, "Byte");
    q.make();
    $("#qr-box").innerHTML = q.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
  } catch {
    return toast("Ссылка слишком длинная для QR-кода", true);
  }
  $("#qr-title").textContent = sub.name;
  $("#qr-copy").onclick = () => copyText(sub.url);
  $("#qr-dialog").showModal();
}

function ask({ title, text, ok, danger }) {
  return new Promise(resolve => {
    const d = $("#ask-dialog");
    $("#ask-title").textContent = title;
    $("#ask-text").textContent = text;
    $("#ask-ok").textContent = ok;
    $("#ask-ok").classList.toggle("danger", danger);
    d.onclose = () => resolve(d.returnValue === "ok");
    d.returnValue = "";
    d.showModal();
  });
}

let renameQueue = Promise.resolve();
function renameSubscription(sub) {
  const dialog = $("#rename-dialog");
  const input = $("#rename-input");
  let timer;
  let saved = sub.name;
  input.value = saved;
  function commit() {
    clearTimeout(timer);
    const name = input.value.trim();
    if (!name) return;
    renameQueue = renameQueue.then(async () => {
      if (name === saved) return;
      await call("rename_subscription", { id: sub.id, name });
      saved = name;
      await reload();
    }).catch(() => {}); // call() displays the error; subsequent edits can retry.
  }
  input.oninput = () => {
    input.setCustomValidity(input.value.trim() ? "" : "Введите название подписки");
    clearTimeout(timer);
    timer = setTimeout(commit, 800);
  };
  input.setCustomValidity("");
  dialog.onclose = commit;
  input.onblur = commit;
  dialog.showModal();
  input.select();
}

function openSubMenu(sub) {
  const items = [];
  if (sub.url) {
    items.push(["share", shareLabel(), ""]);
    items.push(["qr", "Показать QR-код", "для другого устройства"]);
  }
  if (sub.web_page_url) items.push(["site", "Сайт", ""]);
  if (sub.support_url) items.push(["support", "Поддержка", ""]);
  items.push(["rename", "Переименовать", ""]);
  items.push(["delete", "Удалить подписку", ""]);
  $("#sub-menu-title").textContent = sub.name;
  $("#sub-menu-list").innerHTML = items
    .map(([k, t, h]) => `<button type="button" data-act="${k}" class="${k === "delete" ? "danger" : ""}">${esc(t)}${h ? `<small>${esc(h)}</small>` : ""}</button>`)
    .join("");
  const menu = $("#sub-menu");
  $$("#sub-menu-list button").forEach((b) => (b.onclick = async () => {
    menu.close();
    const act = b.dataset.act;
    if (act === "share") shareLink(sub);
    if (act === "qr") showQr(sub);
    if (act === "site") openUrl(sub.web_page_url);
    if (act === "support") openUrl(sub.support_url);
    if (act === "rename") renameSubscription(sub);
    if (act === "delete") {
      const yes = await ask({ title: `Удалить «${sub.name}»?`, text: "Серверы этой подписки пропадут из списка. Её можно будет добавить снова по ссылке.", ok: "Удалить", danger: true });
      if (!yes) return;
      await call("remove_subscription", { id: sub.id }, "Удалено");
      activeSub = null;
      await reload();
    }
  }));
  menu.showModal();
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
    $("#add-input").value = isAndroid() ? await invoke("read_clipboard") : await navigator.clipboard.readText();
    $("#add-btn").click();
  } catch {
    toast("Не удалось прочитать буфер обмена — вставьте ссылку вручную (Ctrl+V)", true);
  }
};

$("#scan-btn").onclick = async () => {
  try {
    const text = (await invoke("scan_qr")).trim();
    if (!text) return;
    $("#add-input").value = text;
    $("#add-btn").click();
  } catch (e) {
    toast(String(e), true);
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

/** Список приложений выбранного режима: у каждого режима он свой. */
function appList() {
  return splitDraft.app_mode === "include" ? splitDraft.apps_include : splitDraft.apps_exclude;
}

const APP_TEXT = {
  windows: {
    exclude: "Эти программы работают без VPN, всё остальное — через VPN.",
    include: "Через VPN работают только эти программы, остальные — напрямую.",
    placeholder: "chrome.exe, C:\\Games\\game.exe или папка C:\\Games\\",
    pick: "Выбрать из запущенных",
    title: "Запущенные программы",
    hint: "Имя программы совпадает с именем .exe. Папка с «\\» на конце захватывает все программы внутри.",
  },
  android: {
    exclude: "Эти приложения работают без VPN — например, банки и госуслуги: их трафик идёт напрямую, мимо туннеля.",
    include: "Через VPN работают только эти приложения, остальные — напрямую.",
    placeholder: "Имя пакета, например org.telegram.messenger",
    pick: "Выбрать приложения",
    title: "Приложения",
    hint: "Списки для режимов «кроме выбранных» и «только выбранные» хранятся отдельно.",
  },
};

let appLabels = {};  // id → название (для Android)

function renderSplit() {
  if (!splitDraft) splitDraft = structuredClone(settingsEdits.split ?? data.settings.split);
  const t = APP_TEXT[platform];
  renderAppRoutes();
  $("#route-app").placeholder = t.placeholder;
  $$("#app-mode input").forEach((i) => (i.checked = i.value === splitDraft.app_mode));
  const off = splitDraft.app_mode === "off";
  $("#apps-box").hidden = off;
  if (!off) {
    $("#apps-caption").textContent = t[splitDraft.app_mode];
    const list = appList();
    $("#apps").innerHTML = list
      .map((a, i) => `<span class="chip" title="${esc(a)}">${esc(appLabels[a] ?? a)}<button data-i="${i}" aria-label="Убрать">×</button></span>`)
      .join("") || `<span class="muted">Приложения не выбраны</span>`;
    $$("#apps button").forEach((b) => (b.onclick = () => { appList().splice(+b.dataset.i, 1); splitChanged(); }));
  }
  $("#app-input").placeholder = t.placeholder;
  $("#app-pick").textContent = t.pick;
  $("#apps-hint").textContent = t.hint;
  if (document.activeElement !== $("#proxy-domains")) $("#proxy-domains").value = splitDraft.proxy_domains.join("\n");
  if (document.activeElement !== $("#direct-domains")) $("#direct-domains").value = splitDraft.direct_domains.join("\n");
  $("#ru-direct").checked = splitDraft.ru_direct;
}

$$("#app-mode input").forEach((i) => (i.onchange = () => { splitDraft.app_mode = i.value; splitChanged(); }));
$("#ru-direct").onchange = (e) => { splitDraft.ru_direct = e.target.checked; splitChanged(); };
const lines = (s) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
$("#proxy-domains").oninput = (e) => { splitDraft.proxy_domains = lines(e.target.value); editSetting("split", structuredClone(splitDraft), 800); };
$("#direct-domains").oninput = (e) => { splitDraft.direct_domains = lines(e.target.value); editSetting("split", structuredClone(splitDraft), 800); };

function addApp(name) {
  name = name.trim();
  const list = appList();
  if (name && !list.some((a) => a.toLowerCase() === name.toLowerCase())) list.push(name);
}
function removeApp(name) {
  const list = appList();
  const i = list.findIndex((a) => a.toLowerCase() === name.toLowerCase());
  if (i >= 0) list.splice(i, 1);
}
$("#app-add").onclick = () => { addApp($("#app-input").value); $("#app-input").value = ""; splitChanged(); };
$("#app-input").onkeydown = (e) => { if (e.key === "Enter") $("#app-add").click(); };

function renderAppRoutes() {
  const servers = new Map();
  for (const sub of data.subscriptions) {
    for (const server of sub.servers) {
      if (server.xray || server.outbound) servers.set(server.id, sub.name + " · " + server.name);
    }
  }
  const select = $("#route-target");
  if (!servers.has(select.value)) select.value = "";
  select.querySelector("span").textContent = servers.get(select.value) ?? "Без интернета";
  $("#app-routes").innerHTML = splitDraft.app_routes.map((r, i) =>
    `<div class="row"><span>${esc(appLabels[r.app] ?? r.app)} → ${esc(r.server ? servers.get(r.server) ?? "Сервер недоступен · без интернета" : "Без интернета")}</span>
    <button class="btn" data-i="${i}" aria-label="Удалить правило">Удалить</button></div>`).join("");
  $$("#app-routes button").forEach(b => b.onclick = () => {
    splitDraft.app_routes.splice(+b.dataset.i, 1);
    splitChanged();
  });
}

const pickerListeners = new WeakMap();
function releasePicker(dialog) {
  const registration = pickerListeners.get(dialog);
  pickerListeners.delete(dialog);
  if (registration) registration.then(listener => listener.unregister()).catch(err => toast(String(err), true));
}
function closePicker(dialog) {
  if (dialog.open) dialog.close();
  releasePicker(dialog);
}
function openPicker(dialog) {
  dialog.showModal();
  if (!isAndroid()) return;
  const registration = window.__TAURI__.app.onBackButtonPress(() => closePicker(dialog));
  pickerListeners.set(dialog, registration);
  registration.catch(err => toast(String(err), true));
}
$$(".picker-back").forEach(button => {
  const dialog = button.closest("dialog");
  button.onclick = () => closePicker(dialog);
  dialog.addEventListener("close", () => { if (!dialog.open) releasePicker(dialog); });
});

function renderTargetList() {
  const query = $("#target-search").value.trim();
  const target = $("#route-target").value;
  const groups = [];
  if (!query || "без интернета".includes(query.toLowerCase())) {
    groups.push(`<button type="button" data-target="" aria-pressed="${!target}">Без интернета</button>`);
  }
  for (const sub of data.subscriptions) {
    const matches = matchingServers(sub, query).filter(server => server.outbound || server.xray);
    if (!matches.length) continue;
    const expand = query || matches.some(server => server.id === target) || data.subscriptions.length === 1;
    groups.push(`<details ${expand ? "open" : ""}><summary>${esc(sub.name)} <small>${matches.length}</small></summary>
      ${matches.map(server => `<button type="button" data-target="${esc(server.id)}" aria-pressed="${server.id === target}">
        <span>${esc(server.name)}</span><small>${esc(server.protocol)}</small></button>`).join("")}</details>`);
  }
  $("#target-list").innerHTML = groups.join("") || '<div class="empty">Серверы не найдены</div>';
}
$("#route-target").onclick = () => {
  $("#target-search").value = "";
  renderTargetList();
  openPicker($("#target-dialog"));
};
$("#target-search").oninput = renderTargetList;
$("#target-list").onclick = e => {
  const button = e.target.closest("[data-target]");
  if (!button) return;
  $("#route-target").value = button.dataset.target;
  renderAppRoutes();
  closePicker($("#target-dialog"));
};

function setAppRoute(app) {
  app = app.trim();
  if (!app) return;
  const server = $("#route-target").value || null;
  const existing = splitDraft.app_routes.find(r => r.app.toLowerCase() === app.toLowerCase());
  if (existing) existing.server = server;
  else splitDraft.app_routes.push({ app, server });
}
$("#route-add").onclick = () => {
  setAppRoute($("#route-app").value);
  $("#route-app").value = "";
  splitChanged();
};
let appRequest = 0;
let pickingRoutes = false;
let procs = [];
function renderProcs() {
  const f = $("#proc-filter").value.toLowerCase();
  const selected = pickingRoutes ? splitDraft.app_routes.filter(r => (r.server || "") === $("#route-target").value).map(r => r.app) : appList();
  const chosen = new Set(selected.map((a) => a.toLowerCase()));
  $("#proc-list").innerHTML = procs
    .filter((p) => !f || p.label.toLowerCase().includes(f) || (p.detail ?? "").toLowerCase().includes(f))
    .map((p) => `<label><input type="checkbox" value="${esc(p.id)}" ${chosen.has(p.id.toLowerCase()) ? "checked" : ""} />${esc(p.label)}<small>${esc(p.detail ?? "")}</small></label>`)
    .join("") || `<div class="empty">Ничего не найдено</div>`;
  $$("#proc-list input").forEach((i) => (i.onchange = () => {
    if (pickingRoutes) {
      if (i.checked) setAppRoute(i.value);
      else splitDraft.app_routes = splitDraft.app_routes.filter(r => r.app.toLowerCase() !== i.value.toLowerCase());
    } else if (i.checked) {
      addApp(i.value);
    } else {
      removeApp(i.value);
    }
    splitChanged();
  }));
}
$("#route-pick").onclick = () => openAppPicker(true);
$("#app-pick").onclick = () => openAppPicker(false);
async function openAppPicker(routes) {
  pickingRoutes = routes;
  $("#proc-title").textContent = APP_TEXT[platform].title;
  const dialog = $("#proc-dialog");
  $("#proc-filter").value = "";
  $("#proc-list").textContent = "Загрузка приложений…";
  procs = [];
  const request = ++appRequest;
  openPicker(dialog);
  try {
    const list = await call("list_apps");
    if (!dialog.open || request !== appRequest) return;
    procs = list;
    for (const p of procs) appLabels[p.id] = p.label;
    renderProcs();
  } catch {
    if (dialog.open && request === appRequest) dialog.close();
  }
}
$("#proc-filter").oninput = renderProcs;

function splitChanged() {
  editSetting("split", structuredClone(splitDraft));
  renderSplit();
}

// ---------------------------------------------------------------------------
// настройки
// ---------------------------------------------------------------------------

const FIELDS = [
  ["#s-dns-remote", "dns_remote"], ["#s-dns-direct", "dns_direct"], ["#s-ua", "user_agent"], ["#s-log", "log_level"],
  ["#s-core", "core"], ["#s-mixed", "mixed_port", Number], ["#s-lan-port", "lan_port", Number],
];
const CHECKS = [
  ["#s-ipv6", "ipv6"], ["#s-lan", "allow_lan"], ["#s-auto", "auto_connect"], ["#s-autostart", "autostart"],
  ["#s-killswitch", "kill_switch"], ["#s-fallback", "tun_fallback"], ["#s-notify", "notification"],
  ["#s-autoswitch", "auto_switch"],
];

const settingsEdits = {};
let saveTimer;
let savingSettings = false;
let saveError = "";
const savedSections = new Set();
let settingsVersion = 0;

function validationError(key, value) {
  if (key === "split" && value.app_mode !== "off") {
    const list = value.app_mode === "include" ? value.apps_include : value.apps_exclude;
    if (!list.length) return "Выберите хотя бы одно приложение";
  }
  if (key === "mixed_port" || key === "lan_port") {
    if (key === "mixed_port" && value === 0) return "";
    if (!Number.isInteger(value) || value < 1024 || value > 65535)
      return key === "mixed_port" ? "Допустимый порт — 0 или 1024–65535" : "Допустимый порт — 1024–65535";
  }
  return "";
}

// A mobile WebView can be stopped before the debounce timer or IPC completes.
const pendingKey = "tunnelka.pending-settings.v1";
function pendingChanges() {
  return Object.fromEntries(Object.entries(settingsEdits).filter(([key, value]) => !validationError(key, value)));
}

function rememberChanges() {
  try {
    const pending = pendingChanges();
    if (Object.keys(pending).length) localStorage.setItem(pendingKey, JSON.stringify(pending));
    else localStorage.removeItem(pendingKey);
  } catch { /* In-memory autosave still works if storage is unavailable. */ }
}

function resumeChanges() {
  try {
    const pending = JSON.parse(localStorage.getItem(pendingKey) || "{}");
    for (const [key, value] of Object.entries(pending)) {
      if (Object.hasOwn(data.settings, key) && !Object.hasOwn(settingsEdits, key) && !validationError(key, value))
        settingsEdits[key] = value;
    }
  } catch { /* Ignore an unreadable draft. */ }
  if (Object.keys(settingsEdits).length) flushSettings();
}

function updateSaveStatus() {
  for (const [id, rules] of [["#settings-status", false], ["#split-status", true]]) {
    const edits = Object.entries(settingsEdits).filter(([key]) => (key === "split") === rules);
    const error = edits.map(([key, value]) => validationError(key, value)).find(Boolean);
    $(id).textContent = error || (edits.length ? saveError || "Сохранение…" : savedSections.has(rules) ? "Сохранено" : "");
  }
}

function editSetting(key, value, delay = 0) {
  settingsEdits[key] = value;
  rememberChanges();
  saveError = "";
  updateSaveStatus();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flushSettings, delay);
}

async function flushSettings() {
  clearTimeout(saveTimer);
  saveTimer = undefined;
  if (savingSettings || !data) return;
  const changes = pendingChanges();
  if (!Object.keys(changes).length) return;
  const next = { ...data.settings, ...changes };
  for (const [key, value] of Object.entries(changes)) {
    if (typeof value === "string") next[key] = value.trim();
  }
  savingSettings = true;
  let succeeded = false;
  try {
    if (Object.keys(changes).some(k => JSON.stringify(next[k]) !== JSON.stringify(data.settings[k]))) {
      await invoke("save_settings", { settings: next });
      data.settings = next;
      settingsVersion++;
    }
    for (const [key, value] of Object.entries(changes)) {
      savedSections.add(key === "split");
      if (settingsEdits[key] === value) delete settingsEdits[key];
    }
    saveError = "";
    succeeded = true;
  } catch (err) {
    saveError = "Ошибка сохранения";
    toast(String(err), true);
    // The backend can persist settings before reporting a restart failure.
    try { await reload(); } catch { /* Keep the draft for a retry. */ }
  } finally {
    savingSettings = false;
    rememberChanges();
    updateSaveStatus();
    if (view === "home") renderHome();
    const revised = Object.entries(settingsEdits).some(([k,v]) =>
      !validationError(k,v) && (succeeded || !(k in changes) || changes[k] !== v));
    if (revised && saveTimer === undefined) flushSettings();
  }
}
document.addEventListener("visibilitychange", () => { if (document.hidden) flushSettings(); });
window.addEventListener("pagehide", flushSettings);

function selectCategory(button) {
  for (const b of $$(".settings-categories button")) {
    const active = b === button;
    b.setAttribute("aria-pressed", String(active));
    document.getElementById(b.getAttribute("aria-controls")).hidden = !active;
  }
}
$$(".settings-categories button").forEach(b => b.onclick = () => selectCategory(b));

for (const [sel, key, convert] of FIELDS) {
  $(sel).addEventListener("blur", flushSettings);
  $(sel).addEventListener("input", e => {
    const raw = e.target.value;
    const value = convert && raw !== "" ? convert(raw) : raw;
    e.target.setCustomValidity(validationError(key, value));
    editSetting(key, value, e.target.tagName === "SELECT" ? 0 : 800);
  });
}
for (const [sel, key] of CHECKS) {
  $(sel).addEventListener("change", e => editSetting(key, e.target.checked));
}

const ORDER = {
  type: ["Такой же тип подключения", "например, VLESS XHTTP → VLESS XHTTP в другой стране"],
  country: ["Та же страна", "например, Нидерланды → другой сервер в Нидерландах"],
  subscription: ["Та же подписка", "серверы того же провайдера"],
};
let orderDraft = [];  // [[ключ, включён]]

function orderSummary(list) {
  const on = list.filter(([, v]) => v).map(([k]) => ORDER[k][0].toLowerCase());
  return [...on, "остальные по скорости"].join(" → ").replace(/^./, (c) => c.toUpperCase());
}

function renderOrder() {
  $("#order-list").innerHTML = orderDraft.map(([k, on], i) => `
    <div class="order-item ${on ? "" : "off"}">
      <span class="n">${on ? orderDraft.slice(0, i + 1).filter(([, v]) => v).length : ""}</span>
      <input type="checkbox" data-i="${i}" ${on ? "checked" : ""} aria-label="Использовать шаг" />
      <span>${esc(ORDER[k][0])}<small>${esc(ORDER[k][1])}</small></span>
      <button type="button" class="icon" data-up="${i}" ${i === 0 ? "disabled" : ""} aria-label="Выше"><svg><use href="#i-up" /></svg></button>
      <button type="button" class="icon" data-down="${i}" ${i === orderDraft.length - 1 ? "disabled" : ""} aria-label="Ниже"><svg><use href="#i-down" /></svg></button>
    </div>`).join("");
  $$("#order-list input").forEach((c) => (c.onchange = () => { orderDraft[+c.dataset.i][1] = c.checked; orderChanged(); }));
  const move = (i, d) => { const [x] = orderDraft.splice(i, 1); orderDraft.splice(i + d, 0, x); orderChanged(); };
  $$("[data-up]").forEach((b) => (b.onclick = () => move(+b.dataset.up, -1)));
  $$("[data-down]").forEach((b) => (b.onclick = () => move(+b.dataset.down, 1)));
}

function orderFromSettings() {
  const on = (settingsEdits.switch_order ?? data.settings.switch_order ?? []).filter((k) => ORDER[k]);
  return [...on.map((k) => [k, true]), ...Object.keys(ORDER).filter((k) => !on.includes(k)).map((k) => [k, false])];
}

$("#order-open").onclick = () => {
  orderDraft = orderFromSettings();
  renderOrder();
  $("#order-dialog").showModal();
};
function orderChanged() {
  editSetting("switch_order", orderDraft.filter(([, v]) => v).map(([k]) => k), 350);
  $("#order-summary").textContent = orderSummary(orderFromSettings());
  renderOrder();
}
$("#order-dialog").onclose = flushSettings;
$("#s-autoswitch").onchange = (e) => ($("#order-open").disabled = !e.target.checked);

function renderSettings() {
  const s = { ...data.settings, ...settingsEdits };
  updateSaveStatus();
  $("#order-summary").textContent = orderSummary(orderFromSettings());
  $("#order-open").disabled = !s.auto_switch;
  for (const [sel, key] of FIELDS) if ($(sel).value !== String(s[key])) $(sel).value = s[key];
  for (const [sel, key] of CHECKS) $(sel).checked = s[key];
  $("#lan-info").hidden = !s.allow_lan;
  if (s.allow_lan) showLanAddresses(s.lan_port);
  if (isAndroid() && !renderSettings.battery) { renderSettings.battery = true; renderBattery(); }
}
$("#s-lan").onchange = (e) => {
  if (!e.target.checked && validationError("lan_port", settingsEdits.lan_port)) {
    delete settingsEdits.lan_port;
    $("#s-lan-port").value = data.settings.lan_port;
    $("#s-lan-port").setCustomValidity("");
    updateSaveStatus();
  }
  $("#lan-info").hidden = !e.target.checked;
  if (e.target.checked) showLanAddresses(+$("#s-lan-port").value || data.settings.lan_port);
};
$("#s-lan-port").oninput = (e) => showLanAddresses(+e.target.value || data.settings.lan_port);

// Точку доступа могут включить, пока открыты настройки, — адрес обновляется сам.
setInterval(() => {
  if (isAndroid() && view === "settings" && $("#s-lan").checked) showLanAddresses(+$("#s-lan-port").value || data.settings.lan_port);
}, 5000);

// Адреса телефона в сети точки доступа: их указывают на подключённом устройстве.
async function showLanAddresses(port) {
  let list = [];
  try { list = await invoke("lan_addresses"); } catch { /* */ }
  const kind = (n) => /^(swlan|ap|softap|wlan[1-9])/.test(n) ? "точка доступа" : /^(rndis|ncm|usb)/.test(n) ? "USB-модем" : /^bt/.test(n) ? "Bluetooth" : /^wlan0$/.test(n) ? "Wi-Fi" : n;
  $("#lan-addr").innerHTML = list.length
    ? list.map((a) => `<div><span>Сервер <code>${esc(a.ip)}</code> · порт <code>${port}</code></span><small>${esc(kind(a.name))}</small></div>`).join("")
    : `<div><span class="muted">Включите точку доступа — здесь появится адрес. Порт: <code>${port}</code></span></div>`;
}

// ---- обновление приложения: только по кнопке ----
let updateInfo = null;
$("#update-check").onclick = async () => {
  const b = $("#update-check");
  if (b.classList.contains("busy")) return;
  b.classList.add("busy");
  try {
    updateInfo = await invoke("check_update");
  } catch (e) {
    return toast(`Не удалось проверить обновления: ${e}`, true);
  } finally {
    b.classList.remove("busy");
  }
  if (!updateInfo.available) return toast(`У вас последняя версия — ${updateInfo.current}`);
  const mb = updateInfo.size ? ` · ${(updateInfo.size / 1048576).toFixed(0)} МБ` : "";
  $("#update-title").textContent = `Доступна версия ${updateInfo.latest}`;
  $("#update-sub").textContent = `Сейчас установлена ${updateInfo.current}${mb}. ` + (isAndroid()
    ? "После скачивания откроется окно установки Android."
    : "После скачивания приложение закроется, установится новая версия и запустится снова. VPN на это время отключится.");
  $("#update-notes").textContent = updateInfo.notes.trim();
  $("#update-progress").hidden = true;
  $("#update-go").disabled = false;
  $("#update-later").disabled = false;
  $("#update-dialog").showModal();
};

$("#update-go").onclick = async () => {
  if (!updateInfo) return;
  const go = $("#update-go");
  go.disabled = true;
  $("#update-later").disabled = true;
  const bar = $("#update-progress");
  bar.hidden = false;
  const paint = (got, total) => {
    const pct = total ? Math.round((got / total) * 100) : 0;
    bar.querySelector("i").style.width = `${pct}%`;
    bar.querySelector("span").textContent = total ? `Скачивание… ${pct}%` : "Скачивание…";
  };
  paint(0, 0);
  const timer = setInterval(async () => {
    try { const [got, total] = await invoke("update_progress"); paint(got, total); } catch { /* */ }
  }, 300);
  try {
    await invoke("install_update", { url: updateInfo.url });
    bar.querySelector("i").style.width = "100%";
    bar.querySelector("span").textContent = isAndroid() ? "Подтвердите установку в окне Android" : "Устанавливаю…";
    if (isAndroid()) setTimeout(() => $("#update-dialog").close(), 1500);
  } catch (e) {
    bar.hidden = true;
    toast(String(e), true);
    go.disabled = false;
  } finally {
    clearInterval(timer);
    $("#update-later").disabled = false;
  }
};

$("#open-vpn-settings").onclick = () => call("open_vpn_settings");
$("#open-notify-settings").onclick = () => call("open_notification_settings");
$("#battery-btn").onclick = async () => { await call("open_battery_settings"); setTimeout(renderBattery, 1500); };

let batteryTick = 0;
async function renderBattery() {
  try {
    const free = await invoke("battery_status");
    $("#battery-btn").hidden = free;
    $("#battery-hint").textContent = free
      ? "Работа в фоне не ограничена: система не будет выключать VPN для экономии батареи."
      : "Система может останавливать приложения в фоне для экономии батареи. Чтобы VPN не выключался, разрешите Tunnelka работать без ограничений. На Samsung также уберите Tunnelka из «Спящих приложений».";
  } catch { /* не Android */ }
}

// ---------------------------------------------------------------------------
// журнал
// ---------------------------------------------------------------------------

// «Только приложение» — сообщения самой Tunnelka без сотен строк ядер.
let logFilter = "all";
const ownLine = (x) => /^\[(app|ks|vpn)\]/.test(x);
async function logLines() {
  const l = await invoke("logs");
  return logFilter === "app" ? l.filter(ownLine) : l;
}
async function loadLogs() {
  const box = $("#log-box");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  const l = await logLines();
  box.textContent = l.join("\n") || (logFilter === "app" ? "Сообщений приложения пока нет." : "Журнал пуст. Здесь появятся сообщения ядра после подключения.");
  if (atBottom) box.scrollTop = box.scrollHeight;
}
$$("#log-filter button").forEach((b) => (b.onclick = () => {
  logFilter = b.dataset.f;
  $$("#log-filter button").forEach((x) => x.classList.toggle("active", x === b));
  loadLogs();
}));
$("#logs-copy").onclick = async () => {
  const text = (await logLines()).join("\n");
  if (!text) return toast("Журнал пуст");
  try { await navigator.clipboard.writeText(text); }
  catch {
    const t = document.createElement("textarea");
    t.value = text; document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  toast("Журнал скопирован");
};
$$("[data-link]").forEach((b) => (b.onclick = () => openUrl(b.dataset.link)));
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
    platform = status.platform;
    document.body.classList.add(`p-${platform}`);
    window.__TAURI__?.app?.getVersion?.().then((v) => ($("#app-version").textContent = v)).catch(() => {});
    await reload();
    resumeChanges();
  } catch (e) {
    toast(String(e), true);
  }
  setInterval(poll, 1000);
})();
