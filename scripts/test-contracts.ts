import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

function findForge(): string {
  // 1. Check if forge is directly runnable from PATH
  const testRun = spawnSync("forge", ["--version"], { stdio: "ignore" });
  if (testRun.status === 0) {
    return "forge";
  }

  // 2. Check Windows user foundry path
  if (process.env.USERPROFILE) {
    const winForge = path.join(process.env.USERPROFILE, ".foundry", "bin", "forge.exe");
    if (fs.existsSync(winForge)) {
      return winForge;
    }
  }

  // 3. Check Unix home foundry path
  if (process.env.HOME) {
    const unixForge = path.join(process.env.HOME, ".foundry", "bin", "forge");
    if (fs.existsSync(unixForge)) {
      return unixForge;
    }
  }

  return "forge";
}

function main() {
  const forgeBin = findForge();
  const extraArgs = process.argv.slice(2);
  const forgeArgs = extraArgs.length > 0 ? extraArgs : ["test", "-vv"];

  const res = spawnSync(forgeBin, forgeArgs, {
    stdio: "inherit",
  });

  if (res.status !== 0) {
    process.exit(res.status || 1);
  }
}

main();
