import { spawn } from "node:child_process";

export function runWrangler(argumentsList) {
  const executable = process.env.WRANGLER_BIN || "wrangler";
  return new Promise((resolve, reject) => {
    const child = spawn(executable, argumentsList, { stdio: "inherit" });
    child.once("error", (error) => {
      reject(new Error(`Could not run ${executable}: ${error.message}`));
    });
    child.once("exit", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`Wrangler exited with status ${code ?? "unknown"}.`));
    });
  });
}

export function serviceConfig() {
  return new URL("../wrangler.jsonc", import.meta.url).pathname;
}
