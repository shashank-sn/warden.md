# service

the auth.md service side, built for cloudflare workers. discovery endpoints, agent registration, the claim ceremony, signed assertions, token exchange, and revocation. deploys to your own account.

status: not built yet. work is tracked in the [`service` issues](https://github.com/shashank-sn/warden.md/issues?q=label%3Atrack%3Aservice).

- d1 for state, durable objects for the claim ceremony
- jose for signing and verification
- rfc 7009 revocation and rfc 8935 security events
