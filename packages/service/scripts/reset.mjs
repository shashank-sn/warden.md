import { runWrangler, serviceConfig } from "./wrangler.mjs";

const target = process.argv.includes("--remote") ? "--remote" : "--local";
if (!process.argv.includes("--yes")) {
  throw new Error("Refusing to erase D1 data without --yes.");
}
if (target === "--remote" && !process.argv.includes("--confirm-remote")) {
  throw new Error("Remote reset also requires --confirm-remote.");
}

const databaseName = "warden-auth-md";
const statements = [
  "DELETE FROM event_deliveries",
  "DELETE FROM revocation_events",
  "DELETE FROM event_subscribers",
  "DELETE FROM issued_tokens",
  "DELETE FROM assertion_replays",
  "DELETE FROM agent_claims",
  "DELETE FROM agent_identities",
];
for (const command of statements) {
  await runWrangler([
    "d1",
    "execute",
    databaseName,
    target,
    "--config",
    serviceConfig(),
    "--command",
    command,
  ]);
}
