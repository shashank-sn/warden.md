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

## adding a package

1. add `packages/<name>/package.json` and `tsconfig.json`, extending the root strict config.
2. expose only the package public API through `src/index.ts`; do not import another package's internals.
3. add behavior-level tests under `packages/<name>/test/` and a package readme with setup and failure modes.
4. run `pnpm lint`, `pnpm typecheck`, `pnpm test`, and `pnpm build` from the repository root.
5. use a changeset for a user-visible published CLI change.

## license

mit. by contributing, you agree your work ships under the same license.
