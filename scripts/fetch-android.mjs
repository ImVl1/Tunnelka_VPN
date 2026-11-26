// Скачивает для Android (arm64): ядра sing-box и Xray, базы правил и библиотеку
// туннеля hev-socks5-tunnel. Всё кладётся среди нативных библиотек приложения
// под именами lib*.so — только оттуда Android разрешает запускать программы.
// Запуск: npm run fetch-android

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, lstatSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
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
  const sbAsset = `sing-box-${SING_BOX}-android-arm64.tar.gz`;
  await download(`https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX}/${sbAsset}`, sb);
  await verifyReleaseDigest("SagerNet/sing-box", `v${SING_BOX}`, sbAsset, sb);
  mkdirSync(join(tmp, "sb"));
  execFileSync("tar", ["-xzf", sb, "-C", join(tmp, "sb")]);
  put(find(join(tmp, "sb"), "sing-box"), "libsingbox.so");

  // Xray
  const xr = join(tmp, "xr.zip");
  const xrUrl = `https://github.com/XTLS/Xray-core/releases/download/v${XRAY}/Xray-android-arm64-v8a.zip`;
  await download(xrUrl, xr);
  await verifyDgst(xrUrl, xr);
  mkdirSync(join(tmp, "xr"));
  if (process.platform === "win32") execFileSync("tar", ["-xf", xr, "-C", join(tmp, "xr")]);
  else execFileSync("unzip", ["-q", xr, "-d", join(tmp, "xr")]);
  put(find(join(tmp, "xr"), "xray"), "libxray.so");

  // The bridge identifies app traffic before tun2socks loses the socket tuple.
  const hev = join(tmp, "hev");
  execFileSync("git", ["clone", "--recursive", "--shallow-submodules", "--depth", "1",
    "--branch", HEV, "https://github.com/heiher/hev-socks5-tunnel", hev], { stdio: "inherit" });
  if (process.platform === "win32") {
    // Git for Windows may check out linked headers as plain files.
    for (const sub of [".", "src/core", "third-part/hev-task-system", "third-part/lwip", "third-part/yaml"]) {
      const cwd = join(hev, sub);
      const entries = execFileSync("git", ["ls-files", "--stage", "-z"], { cwd, encoding: "utf8" });
      for (const entry of entries.split("\0").filter(e => e.startsWith("120000 "))) {
        const header = join(cwd, entry.split("\t")[1]);
        if (!lstatSync(header).isSymbolicLink()) {
          copyFileSync(join(dirname(header), readFileSync(header, "utf8").trim()), header);
        }
      }
    }
  }
  const patches = join(root, "scripts", "android-rules");
  for (const [folder, patch] of [[hev, "hev.patch"], [join(hev, "third-part", "lwip"), "lwip.patch"]]) {
    execFileSync("git", ["apply", join(patches, patch)], { cwd: folder });
  }
  for (const file of ["app-rule.c", "app-rule.h"]) copyFileSync(join(patches, file), join(hev, "src", file));
  const ndk = process.env.NDK_HOME || process.env.ANDROID_NDK_HOME || process.env.ANDROID_NDK_LATEST_HOME;
  if (!ndk) throw new Error("Укажите путь к Android NDK в NDK_HOME");
  execFileSync(join(ndk, process.platform === "win32" ? "ndk-build.cmd" : "ndk-build"),
    ["-j4", "NDK_PROJECT_PATH=.", "APP_BUILD_SCRIPT=Android.mk", "NDK_APPLICATION_MK=Application.mk",
      "APP_ABI=arm64-v8a", "APP_PLATFORM=android-24", "APP_MODULES=hev-socks5-tunnel"],
    { cwd: hev, stdio: "inherit", shell: process.platform === "win32" });
  put(join(hev, "libs", "arm64-v8a", "libhev-socks5-tunnel.so"), "libhev-socks5-tunnel.so");

  // Базы правил для «российские сайты напрямую»
  await download("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs", join(out, "libgeositeru.so"));
  await download("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", join(out, "libgeoipru.so"));

  console.log(`✓ ядра для Android сохранены в ${out}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
