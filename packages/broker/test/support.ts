import { StaticAuthorityResolver, type VerifiedAuthority } from "../src/index.js";

export function createAuthorityResolver(
  entries: readonly Partial<VerifiedAuthority>[] = [{}],
): StaticAuthorityResolver {
  return new StaticAuthorityResolver(
    entries.map((entry) => ({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-a",
      registrationScopes: ["records:write"],
      subjectScopes: ["records:write"],
      resources: ["https://resource.example.test"],
      ...entry,
    })),
  );
}
