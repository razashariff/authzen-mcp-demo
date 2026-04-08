# authzen-mcp-demo

> Reference implementation: an AuthZEN PDP that verifies an RFC 9421 Agent-Signature as a context attribute on an MCP tool call, before making an authorisation decision.
>
> Companion to the **AuthZEN MCP Profile v0.1 discussion draft** ([PDF](https://github.com/razashariff/mcpvs/blob/main/submissions/authzen-mcp-profile-v0.1.pdf)).

---

**Reference implementation only. Not affiliated with the OpenID Foundation.** This repository is an external implementer's reference written to demonstrate that the proposed AuthZEN MCP Profile §1 binding is implementable today, using only standard-library cryptography. The author has not yet executed the OpenID Foundation IPR Contribution Agreement, and this code is not a contribution to the AuthZEN specification text.

---

## What it shows

An AuthZEN PDP receives an authorisation request whose `context` contains an `agent_signature`. The PDP:

1. Reconstructs the canonical request (method, target URI, ISO-8601 timestamp, SHA-256 body hash, agent identity claims)
2. Verifies the signature against the agent's public key (published as a JWKS)
3. Applies its policy
4. Returns a standard AuthZEN decision

If the request body is modified **after** signing (the demo simulates this with a "tamper" flag), the signature fails verification and the decision flips to **Deny**.

## Why this exists

The AuthZEN MCP Profile §1 currently maps token claims to the AuthZEN subject, but does not specify how the PEP establishes that the message presenting the token actually originated from the claimed subject and that the arguments have not been modified in flight. This demo shows that the gap can be closed with a profile of [RFC 9421 -- HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), the same shape as the Mastodon, ActivityPub, and payment-network profiles of RFC 9421. No new cryptography. No changes to the AuthZEN core API.

The full rationale is in the [discussion draft PDF](https://github.com/razashariff/mcpvs/blob/main/submissions/authzen-mcp-profile-v0.1.pdf).

## Run it

```bash
git clone https://github.com/razashariff/authzen-mcp-demo
cd authzen-mcp-demo
node server.js
```

Open <http://localhost:3300>.

Zero npm dependencies. Node 18+ standard library only. The signing key is generated fresh on every server start.

### Smoke test

```bash
node server.js &
node test.js
```

## Endpoints

| Method | Path                            | Description                                                                  |
|--------|---------------------------------|------------------------------------------------------------------------------|
| GET    | `/`                             | Demo HTML page with try-it buttons                                           |
| GET    | `/.well-known/jwks.json`        | Demo agent's public key (JWKS, ES256)                                        |
| GET    | `/jwks.json`                    | Same as above, alternate path                                                |
| GET    | `/health`                       | Liveness probe                                                               |
| POST   | `/access/v1/evaluation`         | AuthZEN v1 PDP API. Accepts an evaluation request with `context.agent_signature`. |
| POST   | `/demo/tool-call`               | Simulates a full MCP tool call going through the PDP. Body: `{"tamper":false}` |
| POST   | `/demo/tamper-test`             | Runs the honest and tampered cases in one call                               |

## Canonical request format

The MCP profile of RFC 9421 specifies a deterministic input format that gets signed:

```
POST
/mcp
2026-04-08T22:30:00Z
sha256=<hex digest of the exact request body bytes>
agent_id=<agent identifier>
on_behalf_of=<principal identifier>
```

Verification is purely local: the verifier reconstructs the canonical request from the wire and calls `crypto.verify` against the published JWKS. **No network call to any third party. No SDK. No license.**

## AuthZEN evaluation request shape

The PDP accepts the standard AuthZEN v1 request shape with one additional context attribute:

```json
{
  "subject": {
    "type": "agent",
    "id": "agent.demo.authzen-mcp.example",
    "properties": {
      "agent_id": "agent.demo.authzen-mcp.example",
      "on_behalf_of": "user@example.com",
      "trust_level": "L2"
    }
  },
  "action":   { "name": "tools/call" },
  "resource": { "type": "mcp_tool", "id": "transfer_funds", "properties": { "amount": 100 } },
  "context": {
    "transport": "http",
    "agent_signature": {
      "algorithm": "ES256",
      "kid": "demo-agent-key-1",
      "header": "Agent-Signature: keyid=\"demo-agent-key-1\", alg=\"ES256\", sig=:...:",
      "canonical_request": "POST\n/mcp\n2026-04-08T22:30:00Z\nsha256=...\nagent_id=...\non_behalf_of=...",
      "signature": "<base64 ecdsa p-256 signature>"
    }
  }
}
```

Response:

```json
{
  "decision": true,
  "context": {
    "id": "ab12cd34",
    "reason_admin": {
      "signature_verified": true,
      "signature_reason": "signature_valid",
      "action_allowed": true,
      "policy": "demo-allowlist",
      "agent_id": "agent.demo.authzen-mcp.example",
      "on_behalf_of": "user@example.com"
    }
  }
}
```

## What this is NOT

- Not a complete AuthZEN PDP implementation. The policy engine is a 5-line allow-list. In production, the PDP would dispatch to OPA, Cedar, Cerbos, OpenFGA, Topaz, Axiomatics, or any other AuthZEN-compatible engine.
- Not a complete RFC 9421 implementation. Production implementations should use a hardened RFC 9421 library and a key-management service.
- Not a contribution to the AuthZEN specification text. See the IPR statement above.
- Not a vendor pitch. The signing layer is free, open, and verifiable by any implementer with a copy of the spec.

## Related work

- [AuthZEN MCP Profile v0.1 discussion draft (PDF)](https://github.com/razashariff/mcpvs/blob/main/submissions/authzen-mcp-profile-v0.1.pdf)
- [OWASP MCP Verification Standard (MCPVS) -- holding repo](https://github.com/razashariff/mcpvs) (proposed; submitted as PPS-86 on 8 April 2026, pending OWASP Project Committee review)
- IETF: [draft-sharif-mcps-secure-mcp](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)
- IETF: [draft-sharif-agent-identity-framework](https://datatracker.ietf.org/doc/draft-sharif-agent-identity-framework/)
- IETF: [draft-sharif-openid-agent-identity](https://datatracker.ietf.org/doc/draft-sharif-openid-agent-identity/)
- [RFC 9421 -- HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 8941 -- Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc8941.html)

## License

MIT. See [LICENSE](./LICENSE).

## Author

Raza Sharif (FBCS, CISSP, CSSLP) -- author of *Breach 20/20* (data breach prevention) -- founder of CyberSecAI Ltd.

raza@cybersecai.co.uk
