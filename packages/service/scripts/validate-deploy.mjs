import { readFile } from "node:fs/promises";

const [
  configText,
  initialMigration,
  hardeningMigration,
  claimRoutesMigration,
  router,
  claimDurableObject,
  eventDelivery,
] = await Promise.all([
  readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
  readFile(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8"),
  readFile(new URL("../migrations/0002_service_hardening.sql", import.meta.url), "utf8"),
  readFile(new URL("../migrations/0003_claim_routes.sql", import.meta.url), "utf8"),
  readFile(new URL("../src/router.ts", import.meta.url), "utf8"),
  readFile(new URL("../src/claim-durable-object.ts", import.meta.url), "utf8"),
  readFile(new URL("../src/event-delivery-durable-object.ts", import.meta.url), "utf8"),
]);
const migrations = `${initialMigration}\n${hardeningMigration}\n${claimRoutesMigration}`;

let config;
try {
  config = JSON.parse(configText);
} catch {
  throw new Error("wrangler.jsonc must remain JSON-compatible.");
}

if (
  config.name !== "warden-auth-md" ||
  config.main !== "src/index.ts" ||
  !Array.isArray(config.d1_databases) ||
  config.d1_databases.length !== 1
) {
  throw new Error("Wrangler config must define the reference Worker and one D1 binding.");
}

const database = config.d1_databases[0];
if (
  database?.binding !== "DB" ||
  database.database_name !== "warden-auth-md" ||
  database.migrations_dir !== "migrations" ||
  typeof database.database_id !== "string" ||
  !database.database_id
) {
  throw new Error("Wrangler D1 binding is incomplete.");
}

for (const [bindingName, className, migrationTag] of [
  ["CLAIM_CEREMONY", "ClaimCeremonyDurableObject", "v1"],
  ["EVENT_DELIVERY", "EventDeliveryDurableObject", "v2"],
]) {
  const binding = config.durable_objects?.bindings?.find(
    (entry) => entry?.name === bindingName && entry.class_name === className,
  );
  const migration = config.migrations?.some(
    (entry) =>
      entry?.tag === migrationTag &&
      Array.isArray(entry.new_classes) &&
      entry.new_classes.includes(className),
  );
  if (!binding || !migration) {
    throw new Error(`Wrangler config must bind and migrate ${className}.`);
  }
}

if (
  !claimDurableObject.includes("class ClaimCeremonyDurableObject") ||
  !claimDurableObject.includes("DurableObjectClaimState") ||
  !claimDurableObject.includes("alarm()") ||
  !eventDelivery.includes("class EventDeliveryDurableObject") ||
  !eventDelivery.includes("alarm()") ||
  !router.includes("CLAIM_CEREMONY") ||
  !router.includes("EVENT_DELIVERY") ||
  !router.includes("D1ClaimRouteRepository")
) {
  throw new Error(
    "Durable Object routing, claim-code lookup, expiry, or retry wiring is incomplete.",
  );
}

for (const table of [
  "agent_identities",
  "agent_claims",
  "assertion_replays",
  "rate_limit_buckets",
  "issued_tokens",
  "event_subscribers",
  "revocation_events",
  "event_deliveries",
  "identity_attempt_audit",
  "claim_routes",
]) {
  if (!migrations.includes(`CREATE TABLE IF NOT EXISTS ${table}`)) {
    throw new Error(`Migration is missing ${table}.`);
  }
}

for (const route of [
  '"/agent/identity/claim"',
  '"/agent/identity/claim/complete"',
  '"/oauth2/token"',
  '"/oauth2/revoke"',
]) {
  if (!router.includes(route)) {
    throw new Error(`Router is missing canonical route ${route}.`);
  }
}

console.log("Deployment template, migrations, Durable Objects, and canonical routes are valid.");
