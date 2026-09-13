# service demo

The default command starts an in-memory HTTP service on an ephemeral localhost port, then runs and verifies this full flow before it exits:

1. anonymous registration;
2. claim start, user-code verification, approval, and poll;
3. one-use claim-grant exchange;
4. a local protected-resource request validated through `validateAccessToken`;
5. revocation and confirmation that the same Bearer token is rejected.

```sh
pnpm demo:service
```

The command creates a new ES256 key only in memory and does not print the user code, device code, claim grant, access token, assertion, service secret, or private key.

To leave the service up after the same verified flow, use a fixed or default port and inspect discovery manually:

```sh
pnpm demo:service -- --serve
curl -sS http://localhost:8788/auth.md
curl -sS http://localhost:8788/.well-known/oauth-protected-resource
curl -sS http://localhost:8788/.well-known/oauth-authorization-server
```

While `--serve` is running, `GET /protected` accepts a valid Bearer token only while its persisted record is active. The process is local and memory-only; it is not a persistent identity provider or a Cloudflare deployment.
