# contributing

short version: pick an issue, open a pr against `initial`, keep it small, make the tests pass.

## first steps

1. browse the issues. `good first issue` is real, and it's accurate.
2. set up: `pnpm install`, then `pnpm test`.
3. comment on the issue you want so two people don't build the same thing.

## ground rules

- every pr needs tests. security-relevant code needs negative tests.
- one issue per pr where possible. small and single-purpose beats big and clever.
- run lint, typecheck, and tests before pushing. ci runs the same commands.
- no credentials, tokens, or real account data in tests, fixtures, or logs. ever.
- found a security problem? don't open a public issue. see [security.md](./SECURITY.md).

## style

- the repo defaults win: typescript strict, formatter and linter run in ci, run the fix command before pushing.
- write commit messages that explain why, not just what.
- comments are for the non-obvious. the code should explain itself otherwise.

## license

mit. by contributing, you agree your work ships under the same license.
