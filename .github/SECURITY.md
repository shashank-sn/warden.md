# security policy

## reporting

use github's private vulnerability reporting on this repo (security tab, then report a vulnerability). if you can't use it, email shashanksn@gmail.com.

please don't open a public issue for a vulnerability.

## scope

this repo's code: the cli, the service, the broker, and the specs we write. not third-party platforms or their protocols.

## what to expect

this project is pre-alpha, so fixes depend on severity and how settled the design is. we'll acknowledge your report, keep you posted while we work, and credit you if you want.

## design commitments

- credentials are short-lived, audience-bound, and single-use where possible.
- revocation paths are tested. a credential that can't be revoked is a bug, not a tradeoff.
- no secrets in logs, fixtures, or error responses. ever.
