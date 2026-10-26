// Скачивает ядра sing-box и Xray-core для Windows и наборы правил geosite/geoip (RU)
// в src-tauri/resources. Запуск: npm run fetch-core
//
// Версии можно переопределить: SING_BOX_VERSION=1.14.4 XRAY_VERSION=26.10.21 npm run fetch-core

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, copyFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = process.env.SING_BOX_VERSION || "1.14.4";
const XRAY_VERSION = process.env.XRAY_VERSION || "26.10.21";
const ARCH = process.env.SING_BOX_ARCH || "amd64"; // amd64 | arm64 | 386
const XRAY_ARCH = { amd64: "64", arm64: "arm64-v8a", "386": "32" }[ARCH];
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "src-tauri", "resources");
mkdirSync(out, { recursive: true });

async function download(url, dest) {
  process.stdout.write(`↓ ${url}\n`);
  const r = await fetch(url, { redirect: "follow" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
}

function findFile(dir, name) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      const f = findFile(p, name);
      if (f) return f;
    } else if (e === name) return p;
  }
  return null;
}

const tmp = mkdtempSync(join(tmpdir(), "singbox-"));
try {
  async function fetchExe(url, name) {
    const zip = join(tmp, `${name}.zip`);
    await download(url, zip);
    const ex = join(tmp, name);
    mkdirSync(ex);
    // tar в Windows 10+ умеет распаковывать zip; в Linux/macOS используем unzip.
    if (process.platform === "win32") execFileSync("tar", ["-xf", zip, "-C", ex]);
    else execFileSync("unzip", ["-q", zip, "-d", ex]);
    const exe = findFile(ex, name);
    if (!exe) throw new Error(`в архиве нет ${name}`);
    copyFileSync(exe, join(out, name));
  }

  await fetchExe(
    `https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-windows-${ARCH}.zip`,
    "sing-box.exe"
  );
  // Xray нужен для XHTTP, VLESS Encryption и режима «всегда Xray».
  await fetchExe(
    `https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-windows-${XRAY_ARCH}.zip`,
    "xray.exe"
  );

  await download(
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
    join(out, "geosite-category-ru.srs")
  );
  await download(
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
    join(out, "geoip-ru.srs")
  );
  console.log(`✓ sing-box ${VERSION}, Xray ${XRAY_VERSION} (${ARCH}) и наборы правил сохранены в ${out}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (!existsSync(join(out, "sing-box.exe")) || !existsSync(join(out, "xray.exe"))) process.exit(1);
