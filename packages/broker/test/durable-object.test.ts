import { describe, expect, it } from "vitest";
import { Broker, type Clock, createDpopSession, GrantExpiryDurableObject } from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

class FakeClock implements Clock {
  public constructor(private time = 0) {}
  public now(): number {
    return this.time;
  }
}

describe("GrantExpiryDurableObject", () => {
  it("finalizes the scheduled grant through the same expiry path", async () => {
    const clock = new FakeClock(1_000);
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([{ subjectId: "subject-a" }]),
    });
    const session = await createDpopSession();
    const proposal = await broker.exchange({
      agentId: "agent-a",
      subjectId: "subject-a",
      subjectTokenId: "subject-token-a",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    });
    const values = new Map<string, unknown>();
    let scheduled: number | Date | undefined;
    const alarm = new GrantExpiryDurableObject(
      {
        storage: {
          async get<T>(key: string) {
            return values.get(key) as T | undefined;
          },
          async put<T>(key: string, value: T) {
            values.set(key, value);
          },
          async setAlarm(value: number | Date) {
            scheduled = value;
          },
        },
      },
      broker,
    );

    await alarm.schedule(proposal.grant.id, proposal.grant.expiresAt);
    await alarm.alarm();

    expect(scheduled).toBe(proposal.grant.expiresAt);
    expect(await broker.getEvidence(proposal.grant.id)).toMatchObject({ completionSource: "ttl" });
  });
});
