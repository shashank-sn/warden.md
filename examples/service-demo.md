# self-hosted service demo

Run the [memory-only HTTP demo](service-demo/README.md) to execute anonymous registration through claim approval, token exchange, protected-resource validation, and revocation rejection. It creates cryptographic material only in memory and prints no credential material.

For a Cloudflare D1-backed Worker, follow [the deployment guide](../docs/deploy.md). The deploy guide covers the resource audience allowlist, per-registration claim Durable Objects, event retry alarms, key retention, provisioning, and offline template validation.
