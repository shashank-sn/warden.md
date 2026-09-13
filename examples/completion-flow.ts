import {
  Broker,
  createDpopSession,
  createWorkersHandler,
  StaticAuthorityResolver,
} from "../packages/broker/src/index.js";

async function main(): Promise<void> {
  const audience = "https://demo.resource.test";
  const broker = await Broker.create({
    policy: { version: 1, default: "require-approval", rules: [] },
    authorityResolver: new StaticAuthorityResolver([
      {
        agentId: "demo-agent",
        subjectId: "demo-user",
        subjectTokenId: "demo-validated-subject",
        registrationScopes: ["work:write"],
        subjectScopes: ["work:write"],
        resources: [audience],
      },
    ]),
    revocationTargets: ["https://demo.resource.test/events"],
  });
  const session = await createDpopSession();
  const proposal = await broker.exchange({
    agentId: "demo-agent",
    subjectId: "demo-user",
    subjectTokenId: "demo-validated-subject",
    resource: audience,
    action: "POST /work-items/42/complete",
    requestedScope: ["work:write"],
    dpopThumbprint: session.thumbprint,
  });
  const approved = await broker.approve(proposal.grant.id, "demo-approver");
  if (!approved.credential) {
    throw new Error("approval did not mint a credential");
  }
  const requestUrl = `${audience}/work-items/42/complete`;
  const handler = createWorkersHandler({ broker, audience }, async () =>
    Response.json({ result: "completed" }),
  );
  const protectedResponse = await handler(
    new Request(requestUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${approved.credential}`,
        dpop: (await session.proof("POST", requestUrl, { now: () => Date.now() })).token,
      },
    }),
  );
  const evidence = await broker.complete(approved.grant.id);
  console.log(
    JSON.stringify({
      grantId: approved.grant.id,
      protectedResponse: protectedResponse.status,
      evidenceId: evidence.id,
      finalState: (await broker.getEvidence(approved.grant.id)) ? "revoked" : "unknown",
    }),
  );
}

void main();
