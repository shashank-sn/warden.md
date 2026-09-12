# vision

## the loop

an agent asks for access to your app. it gets a credential scoped to exactly what it needs. you confirm the request. when the work is done, access is revoked automatically.

registration, scoping, consent, revocation. four steps, one loop, and the loop is mostly missing at the tail.

## what exists today

the pieces are real, and they're getting better.

- registration: auth.md gives agents a discovery file and an oauth-based registration flow. cloudflare, firecrawl, and neon already use it in production.
- scoping: oauth has the vocabulary (scopes, resource indicators, rich authorization requests), and the identity assertion work (id-jag, cross-app access) is turning it into a standard for agents.
- custody: proxies and local gateways (executor, ghostget) keep credentials out of the agent's hands and put policies in front of tool calls.

what's missing is the end of the loop. nobody knows when an agent is done, so nobody revokes on completion. tokens expire on a timer or linger forever, and "scoped" stops meaning much when the scope lives for weeks.

## what we build

three pieces that close the loop:

1. `check`: a conformance toolkit that tells a service exactly what's missing to be agent ready.
2. `service`: a self-hostable auth.md implementation on cloudflare workers. your auth, your database, no vendor account in the middle.
3. `broker`: completion-scoped grants. the agent proposes an exact action, a human approves once, the credential works exactly once, and completion kills the authority and keeps the evidence.

## principles

- the protocol stays open. we implement auth.md and the rfcs it builds on. we don't fork them and we don't compete with them.
- self-hosting is the default, not the fallback.
- credentials are guilty until proven innocent: short-lived, audience-bound, single-use, revocable.
- every design decision should survive being read by one person at 2am.

## non-goals

- a hosted identity provider. we're building the code you run, not a platform you rent.
- payments. agent commerce has its own protocols now.
- replacing anyone's existing stack. the service is compatible with auth.md, and the broker composes with whatever registration you already have.

## how we'll know it worked

- a stranger can deploy the service to their own account and pass conformance in one sitting.
- an agent completes a scoped task and the credential is dead before the result is even read.
- nobody has to ask "what is this agent still allowed to do?", because the answer is nothing.
