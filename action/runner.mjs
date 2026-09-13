import { renderReport } from "./lib/report.mjs";
import { finishAction, prepareAction, runCheck } from "./lib/runtime.mjs";

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

const mode = process.argv[2];

try {
  if (mode === "prepare") {
    prepareAction();
  } else if (mode === "check") {
    process.exitCode = runCheck();
  } else if (mode === "report") {
    renderReport();
  } else if (mode === "finish") {
    process.exitCode = finishAction();
  } else {
    throw new Error("Expected one of: prepare, check, report, finish");
  }
} catch (error) {
  process.stderr.write(`Warden action failed: ${errorMessage(error)}\n`);
  process.exitCode = 1;
}
