import { runWrangler, serviceConfig } from "./wrangler.mjs";

const target = process.argv.includes("--remote") ? "--remote" : "--local";
if (target === "--remote" && !process.argv.includes("--yes")) {
  throw new Error("Remote seeding requires --yes.");
}

const databaseName = "warden-auth-md";
const command = [
  "INSERT OR IGNORE INTO agent_identities",
  "(id, identity_type, scopes_json, resource, client_id, subject, created_at)",
  "VALUES ('demo-service', 'service_auth', '[\"agent:read\"]', 'https://example.invalid', 'demo-client', 'demo-service', 0)",
].join(" ");
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
console.log("Seeded only a non-secret demo identity; no token, assertion, or key was written.");
