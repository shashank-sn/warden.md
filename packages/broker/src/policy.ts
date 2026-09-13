import type { Clock, GrantProposal, PolicyDecision, PolicyDocument, PolicyRule } from "./types.js";

export interface PolicyMatch {
  decision: PolicyDecision;
  ruleId?: string;
}

export class PolicyEngine {
  public constructor(
    private readonly document: PolicyDocument,
    private readonly clock: Clock,
  ) {}

  public decide(proposal: GrantProposal): PolicyMatch {
    const rule = this.document.rules.find((candidate) => this.matches(candidate, proposal));
    return rule
      ? { decision: rule.decision, ruleId: rule.id }
      : { decision: this.document.default };
  }

  private matches(rule: PolicyRule, proposal: GrantProposal): boolean {
    const match = rule.match;
    if (!match) {
      return true;
    }

    if (match.agentId && match.agentId !== proposal.agentId) {
      return false;
    }
    if (match.resource && match.resource !== proposal.resource) {
      return false;
    }
    if (match.action && match.action !== proposal.action) {
      return false;
    }
    if (match.scope) {
      const expected = new Set(match.scope);
      const requested = new Set(proposal.requestedScope);
      if (
        expected.size !== requested.size ||
        [...expected].some((scope) => !requested.has(scope))
      ) {
        return false;
      }
    }
    if (match.timeWindow) {
      const hour = new Date(this.clock.now()).getUTCHours();
      const { startHourInclusive, endHourExclusive } = match.timeWindow;
      const spansMidnight = startHourInclusive > endHourExclusive;
      const inWindow = spansMidnight
        ? hour >= startHourInclusive || hour < endHourExclusive
        : hour >= startHourInclusive && hour < endHourExclusive;
      if (!inWindow) {
        return false;
      }
    }
    return true;
  }
}
