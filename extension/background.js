"use strict";

// Режимы:
//  app    — трафик браузера идёт в приложение Tunnelka (порт ext_port), а оно уже
//           подключается по VLESS/VMess/Trojan/Hysteria2 и т.д.
//  direct — браузер сам ходит через HTTP/HTTPS/SOCKS-прокси (без приложения).
// Какие сайты идут через прокси, решает PAC-скрипт: все / только список / все кроме списка.

const DEFAULTS = {
  enabled: false,
  mode: "app",
  app: { port: 2082, token: "" },
  direct: { servers: [], selected: null },
  routing: { type: "all", domains: [] },
  webrtc: true,
};

let effective = { active: false, error: null, appStatus: null, controlled: true };

async function getState() {
  const s = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return {
    ...DEFAULTS,
    ...s,
    app: { ...DEFAULTS.app, ...(s.app || {}) },
    direct: { ...DEFAULTS.direct, ...(s.direct || {}) },
    routing: { ...DEFAULTS.routing, ...(s.routing || {}) },
  };
}

// ---------------------------------------------------------------------------
// API приложения
// ---------------------------------------------------------------------------

async function appApi(path, method = "GET", body, timeout = 5000) {
  const st = await getState();
  let resp;
  try {
    resp = await fetch(`http://127.0.0.1:${st.app.port}${path}`, {
      method,
      headers: { "X-Tunnelka-Token": st.app.token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeout),
      cache: "no-store",
    });
  } catch {
    throw new Error("Приложение Tunnelka не запущено или указан неверный порт API");
  }
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(json.error || `Ошибка приложения (${resp.status})`);
  return json;
}

// ---------------------------------------------------------------------------
// PAC
// ---------------------------------------------------------------------------

function normDomain(d) {
  d = String(d).trim().toLowerCase();
  if (!d || d.startsWith("#")) return null;
  d = d.replace(/^[a-z]+:\/\//, "").split(/[/?#]/)[0].split(":")[0];
  d = d.replace(/^\*\./, "").replace(/^\./, "").replace(/\.$/, "");
  return /^[a-z0-9.\-_Ѐ-ӿ]+$/.test(d) ? d : null;
}

function buildPac(proxy, routing) {
  const list = [...new Set(routing.domains.map(normDomain).filter(Boolean))];
  const type = routing.type;
  return `
var P = ${JSON.stringify(proxy)};
var L = ${JSON.stringify(list)};
var T = ${JSON.stringify(type)};
function inList(h) {
  for (var i = 0; i < L.length; i++) {
    var d = L[i];
    if (h === d) return true;
    var n = h.length - d.length;
    if (n > 0 && h.charAt(n - 1) === "." && h.substring(n) === d) return true;
  }
  return false;
}
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (isPlainHostName(host) || host === "localhost" || /\\.local$/.test(host) ||
      shExpMatch(host, "127.*") || shExpMatch(host, "10.*") || shExpMatch(host, "192.168.*") ||
      /^172\\.(1[6-9]|2[0-9]|3[01])\\./.test(host) || host === "[::1]") return "DIRECT";
  if (T === "include") return inList(host) ? P : "DIRECT";
  if (T === "exclude") return inList(host) ? "DIRECT" : P;
  return P;
}`;
}

function directProxyString(srv) {
  const hp = `${srv.host}:${srv.port}`;
  switch (srv.scheme) {
    case "socks5": return `SOCKS5 ${hp}`;
    case "socks4": return `SOCKS ${hp}`;
    case "https": return `HTTPS ${hp}`;
    default: return `PROXY ${hp}`;
  }
}

// ---------------------------------------------------------------------------
// применение настроек
// ---------------------------------------------------------------------------

async function clearProxy() {
  await chrome.proxy.settings.clear({ scope: "regular" });
}

async function setBadge(text, color) {
  await chrome.action.setBadgeText({ text });
  if (color) await chrome.action.setBadgeBackgroundColor({ color });
}

async function setWebRtc(on) {
  try {
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({
      value: on ? "disable_non_proxied_udp" : "default",
    });
  } catch { /* политика может быть закреплена администратором */ }
}

let applying = Promise.resolve();
function apply() {
  applying = applying.then(applyInner, applyInner);
  return applying;
}

async function applyInner() {
  const st = await getState();
  effective = { active: false, error: null, appStatus: null, controlled: true };

  const ctl = await chrome.proxy.settings.get({ incognito: false });
  if (ctl.levelOfControl === "controlled_by_other_extensions" || ctl.levelOfControl === "not_controllable") {
    effective.controlled = false;
  }

  if (st.mode === "app") {
    try {
      effective.appStatus = await appApi("/api/status");
    } catch (e) {
      effective.error = e.message;
    }
  }

  if (!st.enabled) {
    await clearProxy();
    await setWebRtc(false);
    await setBadge("");
    return effective;
  }

  let proxy = null;
  if (st.mode === "app") {
    const s = effective.appStatus;
    if (s?.running) {
      proxy = `SOCKS5 127.0.0.1:${s.ext_port}; PROXY 127.0.0.1:${s.ext_port}`;
    } else if (s) {
      effective.error = "VPN в приложении отключён — нажмите «Подключить»";
    }
  } else {
    const srv = st.direct.servers.find((x) => x.id === st.direct.selected);
    if (srv) proxy = directProxyString(srv);
    else effective.error = "Добавьте и выберите прокси-сервер";
  }

  if (!proxy) {
    // Не оставляем браузер с «мёртвым» прокси — иначе пропадёт интернет.
    await clearProxy();
    await setWebRtc(false);
    await setBadge("!", "#e3a64a");
    return effective;
  }

  await chrome.proxy.settings.set({
    scope: "regular",
    value: { mode: "pac_script", pacScript: { data: buildPac(proxy, st.routing), mandatory: false } },
  });
  await setWebRtc(st.webrtc);
  await setBadge("ON", "#19b3a6");
  effective.active = true;
  if (!effective.controlled) effective.error = "Прокси браузера управляет другое расширение — отключите его";
  return effective;
}

// ---------------------------------------------------------------------------
// авторизация на HTTP-прокси в режиме «свой прокси»
// ---------------------------------------------------------------------------

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) return callback({});
    getState().then((st) => {
      const srv = st.mode === "direct" && st.direct.servers.find((x) => x.id === st.direct.selected);
      if (srv && srv.user) callback({ authCredentials: { username: srv.user, password: srv.pass || "" } });
      else callback({});
    });
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

chrome.proxy.onProxyError.addListener((e) => {
  effective.error = `Ошибка прокси: ${e.error}`;
});

// ---------------------------------------------------------------------------
// жизненный цикл
// ---------------------------------------------------------------------------

chrome.runtime.onStartup.addListener(apply);
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("check", { periodInMinutes: 0.5 });
  apply();
});
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== "check") return;
  const st = await getState();
  if (st.enabled && st.mode === "app") apply();
});

// ---------------------------------------------------------------------------
// сообщения из всплывающего окна
// ---------------------------------------------------------------------------

async function handle(msg) {
  switch (msg.type) {
    case "get":
      await apply();
      return { state: await getState(), effective };
    case "set":
      await chrome.storage.local.set(msg.patch);
      await apply();
      return { state: await getState(), effective };
    case "appServers":
      return appApi("/api/servers");
    case "appConnect":
      await appApi("/api/connect", "POST", msg.server ? { server: msg.server } : {}, 30000);
      await chrome.storage.local.set({ enabled: true });
      await apply();
      return { state: await getState(), effective };
    case "appDisconnect":
      await appApi("/api/disconnect", "POST");
      await apply();
      return { state: await getState(), effective };
    case "appSelect":
      await appApi("/api/select", "POST", { server: msg.server }, 30000);
      await apply();
      return { state: await getState(), effective };
    case "appPing":
      return appApi("/api/ping");
    default:
      throw new Error("unknown message");
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  handle(msg).then(
    (r) => reply({ ok: true, data: r }),
    (e) => reply({ ok: false, error: e.message || String(e) })
  );
  return true;
});
