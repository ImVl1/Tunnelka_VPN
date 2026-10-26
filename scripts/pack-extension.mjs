// Упаковывает расширение в dist/tunnelka-extension.zip (для Chrome Web Store
// или передачи другим). Для установки у себя достаточно «Загрузить распакованное».

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const zip = join(dist, "tunnelka-extension.zip");
mkdirSync(dist, { recursive: true });
rmSync(zip, { force: true });

if (process.platform === "win32") {
  execFileSync("powershell", [
    "-NoProfile", "-Command",
    `Compress-Archive -Path '${join(root, "extension")}\\*' -DestinationPath '${zip}'`,
  ], { stdio: "inherit" });
} else {
  execFileSync("zip", ["-qr", zip, "."], { cwd: join(root, "extension"), stdio: "inherit" });
}
console.log(`✓ ${zip}`);
