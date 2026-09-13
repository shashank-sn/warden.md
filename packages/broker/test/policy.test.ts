import { describe, expect, it } from "vitest";
import { type Clock, type GrantProposal, type PolicyDocument, PolicyEngine } from "../src/index.js";

const clock: Clock = {
  now: () => Date.UTC(2026, 0, 1, 14, 0, 0),
};

const proposal: GrantProposal = {
  agentId: "agent-a",
  subjectId: "person-a",
  subjectTokenId: "subject-a",
  resource: "https://resource.example.test",
  action: "POST /records/42",
  requestedScope: ["records:write"],
  dpopThumbprint: "jkt",
};

describe("policy engine", () => {
  it("requires all structured action, resource, scope, and time fields to match", () => {
    const document: PolicyDocument = {
      version: 1,
      default: "block",
      rules: [
        {
          id: "approve-record-write",
          decision: "require-approval",
          match: {
            agentId: "agent-a",
            resource: "https://resource.example.test",
            action: "POST /records/42",
            scope: ["records:write"],
            timeWindow: { startHourInclusive: 9, endHourExclusive: 17 },
          },
        },
      ],
    };
    const policy = new PolicyEngine(document, clock);

    expect(policy.decide(proposal)).toEqual({
      decision: "require-approval",
      ruleId: "approve-record-write",
    });
    expect(policy.decide({ ...proposal, action: "POST /records/43" })).toEqual({
      decision: "block",
    });
    expect(policy.decide({ ...proposal, resource: "https://attacker.example.test" })).toEqual({
      decision: "block",
    });
  });

  it("supports a time window spanning midnight", () => {
    const nightClock: Clock = { now: () => Date.UTC(2026, 0, 1, 23, 0, 0) };
    const policy = new PolicyEngine(
      {
        version: 1,
        default: "block",
        rules: [
          {
            id: "night-read",
            decision: "allow",
            match: { timeWindow: { startHourInclusive: 22, endHourExclusive: 6 } },
          },
        ],
      },
      nightClock,
    );

    expect(policy.decide(proposal)).toEqual({ decision: "allow", ruleId: "night-read" });
  });
});
