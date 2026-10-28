// Скачивает для Android (arm64): ядра sing-box и Xray, базы правил и библиотеку
// туннеля hev-socks5-tunnel. Всё кладётся среди нативных библиотек приложения
// под именами lib*.so — только оттуда Android разрешает запускать программы.
// Запуск: npm run fetch-android

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SING_BOX = process.env.SING_BOX_VERSION || "1.14.4";
const XRAY = process.env.XRAY_VERSION || "26.10.21";
const HEV = process.env.HEV_VERSION || "2.19.3";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "src-tauri", "gen", "android", "app", "src", "main", "jniLibs", "arm64-v8a");
mkdirSync(out, { recursive: true });

async function download(url, dest) {
  process.stdout.write(`↓ ${url}\n`);
  const r = await fetch(url, { redirect: "follow" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
}

function find(dir, name) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      const f = find(p, name);
      if (f) return f;
    } else if (e === name) return p;
  }
  return null;
}

function put(src, name) {
  if (!src) throw new Error(`не найден файл для ${name}`);
  const dst = join(out, name);
  copyFileSync(src, dst);
  chmodSync(dst, 0o755);
}

const tmp = mkdtempSync(join(tmpdir(), "android-core-"));
try {
  // sing-box
  const sb = join(tmp, "sb.tar.gz");
  await download(`https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX}/sing-box-${SING_BOX}-android-arm64.tar.gz`, sb);
  mkdirSync(join(tmp, "sb"));
  execFileSync("tar", ["-xzf", sb, "-C", join(tmp, "sb")]);
  put(find(join(tmp, "sb"), "sing-box"), "libsingbox.so");

  // Xray
  const xr = join(tmp, "xr.zip");
  await download(`https://github.com/XTLS/Xray-core/releases/download/v${XRAY}/Xray-android-arm64-v8a.zip`, xr);
  execFileSync("unzip", ["-q", xr, "-d", join(tmp, "xr")]);
  put(find(join(tmp, "xr"), "xray"), "libxray.so");

  // hev-socks5-tunnel (готовая сборка из AAR)
  const hev = join(tmp, "hev.aar");
  await download(`https://github.com/heiher/hev-socks5-tunnel/releases/download/${HEV}/hev-socks5-tunnel.aar`, hev);
  execFileSync("unzip", ["-q", hev, "jni/arm64-v8a/*", "-d", join(tmp, "hev")]);
  put(join(tmp, "hev", "jni", "arm64-v8a", "libhev-socks5-tunnel.so"), "libhev-socks5-tunnel.so");

  // Базы правил для «российские сайты напрямую»
  await download("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs", join(out, "libgeositeru.so"));
  await download("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", join(out, "libgeoipru.so"));

  console.log(`✓ ядра для Android сохранены в ${out}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
