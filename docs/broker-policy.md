# broker policy configuration

The broker evaluates structured policy before minting authority. It matches agent identity, exact
resource, exact action, requested scope, and an optional UTC hour window. First matching rule wins;
the document default applies when no rule matches.

```json
{
  "version": 1,
  "default": "require-approval",
  "rules": [
    {
      "id": "allow-profile-read",
      "decision": "allow",
      "match": {
        "agentId": "profile-agent",
        "resource": "https://api.example.test",
        "action": "GET /me",
        "scope": ["profile:read"]
      }
    },
    {
      "id": "approve-payments",
      "decision": "require-approval",
      "match": {
        "resource": "https://payments.example.test",
        "action": "POST /invoices/42/pay",
        "scope": ["payments:write"],
        "timeWindow": { "startHourInclusive": 9, "endHourExclusive": 17 }
      }
    },
    {
      "id": "block-destructive",
      "decision": "block",
      "match": { "action": "DELETE /accounts/42" }
    }
  ]
}
```

- `allow` reserves the validated subject token and mints a single-use credential immediately.
- `require-approval` creates a proposed grant and requires an approval callback before minting.
- `block` creates a denied audit record and never mints a credential.

Policies are not free-form prompts. The approval view must render the broker-resolved action,
audience, and granted scope, so agent text cannot redirect a human decision to another resource.

The deployed runtime rejects unknown fields at every policy level. Rule fields are `id`, `decision`,
and optional `match`; match fields are `agentId`, `resource`, `action`, `scope`, and `timeWindow`.
An empty `match` is rejected—omit `match` only when a deliberately global rule is intended. This keeps
a typo such as `resouce` from silently becoming a global allow rule.
