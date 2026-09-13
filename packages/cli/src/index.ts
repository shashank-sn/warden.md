#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { runCli } from "./cli.js";

if (isCliEntrypoint()) {
  void runCli(process.argv.slice(2)).then((exitCode) => {
    process.exitCode = exitCode;
  });
}

export { runConformanceCheck } from "./check.js";
export { EXIT_CODES, runCli } from "./cli.js";
export type {
  ConformanceReport,
  Finding,
  FindingLocation,
  ProbeHop,
  ReportSummary,
  Severity,
} from "./model.js";
export { type CanonicalConformanceReport, canonicalizeReport } from "./reporter.js";
export type { Transport, TransportRequest, TransportResponse } from "./transport.js";
export { createFetchTransport, TransportError } from "./transport.js";

function isCliEntrypoint(): boolean {
  const entrypoint = process.argv[1];
  if (!entrypoint) {
    return false;
  }

  try {
    return realpathSync(entrypoint) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
