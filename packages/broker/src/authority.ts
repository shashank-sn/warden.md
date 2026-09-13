import type { AuthorityResolver, VerifiedAuthority } from "./types.js";

export class StaticAuthorityResolver implements AuthorityResolver {
  private readonly bySubjectToken = new Map<string, VerifiedAuthority>();

  public constructor(entries: readonly VerifiedAuthority[]) {
    for (const entry of entries) {
      this.bySubjectToken.set(entry.subjectTokenId, {
        ...entry,
        registrationScopes: [...entry.registrationScopes],
        subjectScopes: [...entry.subjectScopes],
        resources: [...entry.resources],
      });
    }
  }

  public async resolve(input: {
    agentId: string;
    subjectId: string;
    subjectTokenId: string;
  }): Promise<VerifiedAuthority | undefined> {
    const authority = this.bySubjectToken.get(input.subjectTokenId);
    if (
      !authority ||
      authority.agentId !== input.agentId ||
      authority.subjectId !== input.subjectId
    ) {
      return undefined;
    }
    return {
      ...authority,
      registrationScopes: [...authority.registrationScopes],
      subjectScopes: [...authority.subjectScopes],
      resources: [...authority.resources],
    };
  }
}

export class RejectingAuthorityResolver implements AuthorityResolver {
  public async resolve(): Promise<undefined> {
    return undefined;
  }
}
