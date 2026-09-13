import { runWrangler, serviceConfig } from "./wrangler.mjs";

const databaseName = process.argv[2] || "warden-auth-md";
if (!/^[a-z0-9][a-z0-9-]{1,62}$/u.test(databaseName)) {
  throw new Error("Database name must use lowercase letters, digits, and hyphens.");
}

await import("./validate-deploy.mjs");
await runWrangler(["d1", "create", databaseName]);
console.log(`\nCopy the returned database_id into ${serviceConfig()}, then run:`);
console.log(`wrangler d1 migrations apply ${databaseName} --remote --config ${serviceConfig()}`);
console.log(`wrangler deploy --config ${serviceConfig()}`);
console.log(
  "Before deploy, set SERVICE_SIGNING_JWK and SERVICE_AUTH_TOKEN with wrangler secret put.",
);
