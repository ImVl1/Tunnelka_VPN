// Скачивает ядра sing-box и Xray-core для Windows и наборы правил geosite/geoip (RU)
// в src-tauri/resources. Запуск: npm run fetch-core
//
// Версии можно переопределить: SING_BOX_VERSION=1.14.4 XRAY_VERSION=26.10.21 npm run fetch-core

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
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

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex").toLowerCase();
}

async function verifyDgst(archiveUrl, file) {
  const r = await fetch(`${archiveUrl}.dgst`, { redirect: "follow" });
  if (!r.ok) throw new Error(`${archiveUrl}.dgst: HTTP ${r.status}`);
  const text = await r.text();
  const m = text.match(/SHA2-256\s*=\s*([0-9a-fA-F]{64})/);
  if (!m) throw new Error(`в ${archiveUrl}.dgst не найден SHA2-256`);
  const actual = sha256(file);
  if (actual !== m[1].toLowerCase()) {
    throw new Error(`не совпал SHA-256 для ${archiveUrl}: ожидался ${m[1].toLowerCase()}, получен ${actual}`);
  }
}

async function verifyReleaseDigest(repo, tag, assetName, file) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "Tunnelka-Build" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const r = await fetch(`https://api.github.com/repos/${repo}/releases/tags/${tag}`, { headers });
  if (!r.ok) {
    if ((r.status === 403 || r.status === 429) && !process.env.GITHUB_TOKEN) {
      console.warn(`⚠ пропуск проверки SHA-256 для ${assetName} (лимит GitHub API без GITHUB_TOKEN)`);
      return;
    }
    throw new Error(`GitHub API ${repo}@${tag}: HTTP ${r.status}`);
  }
  const rel = await r.json();
  const asset = (rel.assets || []).find((a) => a.name === assetName);
  const expected = asset?.digest?.startsWith("sha256:") ? asset.digest.slice(7).toLowerCase() : null;
  if (!expected) return;
  const actual = sha256(file);
  if (actual !== expected) {
    throw new Error(`не совпал SHA-256 для ${assetName}: ожидался ${expected}, получен ${actual}`);
  }
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
  async function fetchExe(url, name, verify) {
    const zip = join(tmp, `${name}.zip`);
    await download(url, zip);
    if (verify) await verify(zip);
    const ex = join(tmp, name);
    mkdirSync(ex);
    // tar в Windows 10+ умеет распаковывать zip; в Linux/macOS используем unzip.
    if (process.platform === "win32") execFileSync("tar", ["-xf", zip, "-C", ex]);
    else execFileSync("unzip", ["-q", zip, "-d", ex]);
    const exe = findFile(ex, name);
    if (!exe) throw new Error(`в архиве нет ${name}`);
    // copy, а не rename: временная папка может быть на другом диске (C: → D:).
    copyFileSync(exe, join(out, name));
  }

  const sbAsset = `sing-box-${VERSION}-windows-${ARCH}.zip`;
  await fetchExe(
    `https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${sbAsset}`,
    "sing-box.exe",
    (zip) => verifyReleaseDigest("SagerNet/sing-box", `v${VERSION}`, sbAsset, zip)
  );
  // Xray нужен для XHTTP, VLESS Encryption и режима «всегда Xray».
  const xrUrl = `https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-windows-${XRAY_ARCH}.zip`;
  await fetchExe(xrUrl, "xray.exe", (zip) => verifyDgst(xrUrl, zip));

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
