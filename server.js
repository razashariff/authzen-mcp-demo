// authzen-mcp-demo
//
// Reference implementation showing how an AuthZEN PDP can verify an
// RFC 9421 Agent-Signature as a context attribute on an MCP tool call,
// before making an authorisation decision.
//
// Companion to the AuthZEN MCP Profile v0.1 discussion draft
// (github.com/razashariff/mcpvs/blob/main/submissions/authzen-mcp-profile-v0.1.pdf).
//
// This is NOT affiliated with the OpenID Foundation. It is an external
// implementer's reference, written to demonstrate that the proposed
// Section 1 binding is implementable today using only standard-library
// cryptography.
//
// (c) 2026 Raza Sharif, CyberSecAI Ltd. MIT licensed.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3300;

// ---------------------------------------------------------------------------
// 1. Demo agent keypair (generated once at startup)
// ---------------------------------------------------------------------------
// In a real deployment, agents generate their own keypairs and publish their
// public key as a JWKS. For the demo we generate one fresh on startup so the
// public key is always discoverable at /jwks.json.

const { privateKey: agentPrivateKey, publicKey: agentPublicKey } =
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

const agentPublicJwk = agentPublicKey.export({ format: 'jwk' });
agentPublicJwk.kid = 'demo-agent-key-1';
agentPublicJwk.use = 'sig';
agentPublicJwk.alg = 'ES256';

const AGENT_ID = 'agent.demo.authzen-mcp.example';
const AGENT_PRINCIPAL = 'user@example.com';
const AGENT_TRUST_LEVEL = 'L2';

// ---------------------------------------------------------------------------
// 2. Canonical request construction (the MCP profile of RFC 9421)
// ---------------------------------------------------------------------------
// This is the heart of the proposal. The canonical request is the deterministic
// input that gets signed. Independent implementations producing the same
// canonical input must produce the same signature for the same key, which is
// what makes the signature interoperable across implementations.
//
// Canonical input format (newline-delimited):
//   <HTTP method, uppercase>
//   <target URI, exact path + query>
//   <ISO-8601 timestamp, second precision, Z>
//   sha256=<hex digest of the exact request body bytes>
//   agent_id=<agent identifier>
//   on_behalf_of=<principal identifier>

function canonicalRequest({ method, targetUri, timestamp, body, agentId, onBehalfOf }) {
  const bodyBytes = Buffer.from(body || '', 'utf8');
  const bodyHash = crypto.createHash('sha256').update(bodyBytes).digest('hex');
  return [
    method.toUpperCase(),
    targetUri,
    timestamp,
    'sha256=' + bodyHash,
    'agent_id=' + agentId,
    'on_behalf_of=' + onBehalfOf
  ].join('\n');
}

function signCanonicalRequest(canonical, privateKey) {
  const sig = crypto.sign('SHA256', Buffer.from(canonical, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return sig.toString('base64');
}

function verifyCanonicalRequest(canonical, signatureB64, publicKey) {
  try {
    return crypto.verify(
      'SHA256',
      Buffer.from(canonical, 'utf8'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64, 'base64')
    );
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 3. AuthZEN PDP -- evaluates an authorisation request that includes an
//    Agent-Signature in its context attribute
// ---------------------------------------------------------------------------
// AuthZEN evaluation request shape (simplified to the v1 PDP API):
//   {
//     subject: { type, id, properties },
//     action:  { name },
//     resource: { type, id, properties },
//     context: { agent_signature: { header, canonical_request } }
//   }
//
// Response:
//   {
//     decision: boolean,
//     context: { reason_admin, signature_verified, policy_decision }
//   }

function authzenEvaluate(req) {
  const ctx = req.context || {};
  const sig = ctx.agent_signature || {};

  // Step 1 -- verify the Agent-Signature against the demo agent's public key
  let signatureVerified = false;
  let signatureReason = 'no_signature_present';

  if (sig.canonical_request && sig.signature) {
    signatureVerified = verifyCanonicalRequest(sig.canonical_request, sig.signature, agentPublicKey);
    signatureReason = signatureVerified ? 'signature_valid' : 'signature_invalid_or_tampered';
  }

  // Step 2 -- evaluate the actual policy. For the demo this is a simple
  // allow-list of MCP methods. In production this would dispatch to OPA,
  // Cedar, Cerbos, OpenFGA, Topaz, or any other AuthZEN-compatible engine.
  const allowedActions = ['tools/call', 'tools/list', 'resources/read', 'resources/list'];
  const actionAllowed = allowedActions.includes((req.action || {}).name);

  // Step 3 -- final decision. The signature must verify AND the policy must allow.
  const decision = signatureVerified && actionAllowed;

  return {
    decision,
    context: {
      id: crypto.randomBytes(8).toString('hex'),
      reason_admin: {
        signature_verified: signatureVerified,
        signature_reason: signatureReason,
        action_allowed: actionAllowed,
        policy: 'demo-allowlist',
        agent_id: ((req.subject || {}).properties || {}).agent_id || null,
        on_behalf_of: ((req.subject || {}).properties || {}).on_behalf_of || null
      }
    }
  };
}

// ---------------------------------------------------------------------------
// 4. Helper: build a complete AuthZEN evaluation request from a demo MCP call
// ---------------------------------------------------------------------------

function buildEvaluationRequest({ method, targetUri, body, tamper }) {
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // Build canonical request (signer's view)
  const canonical = canonicalRequest({
    method,
    targetUri,
    timestamp,
    body,
    agentId: AGENT_ID,
    onBehalfOf: AGENT_PRINCIPAL
  });

  // Sign it with the agent's private key
  const signature = signCanonicalRequest(canonical, agentPrivateKey);

  // If the tamper flag is set, modify the body AFTER signing -- this simulates
  // an attacker (or buggy gateway) modifying the request in flight. The
  // verifier will recompute the canonical request from the (tampered) body
  // and the signature will fail.
  let presentedBody = body;
  let presentedCanonical = canonical;
  if (tamper) {
    presentedBody = body.replace(/"amount":\s*\d+/, '"amount": 999999');
    presentedCanonical = canonicalRequest({
      method,
      targetUri,
      timestamp,
      body: presentedBody,
      agentId: AGENT_ID,
      onBehalfOf: AGENT_PRINCIPAL
    });
  }

  let parsedBody;
  try {
    parsedBody = JSON.parse(presentedBody);
  } catch (e) {
    parsedBody = { raw: presentedBody };
  }

  return {
    subject: {
      type: 'agent',
      id: AGENT_ID,
      properties: {
        agent_id: AGENT_ID,
        on_behalf_of: AGENT_PRINCIPAL,
        trust_level: AGENT_TRUST_LEVEL
      }
    },
    action: {
      name: (parsedBody && parsedBody.method) || 'tools/call'
    },
    resource: {
      type: 'mcp_tool',
      id: ((parsedBody || {}).params || {}).name || 'unknown',
      properties: ((parsedBody || {}).params || {}).arguments || {}
    },
    context: {
      transport: 'http',
      timestamp,
      target_uri: targetUri,
      tampered: !!tamper,
      agent_signature: {
        algorithm: 'ES256',
        kid: agentPublicJwk.kid,
        header: 'Agent-Signature: keyid="' + agentPublicJwk.kid + '", alg="ES256", sig=:' + signature + ':',
        canonical_request: presentedCanonical,
        signature
      }
    }
  };
}

// ---------------------------------------------------------------------------
// 5. HTTP server
// ---------------------------------------------------------------------------

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    ...headers
  });
  res.end(typeof body === 'string' ? body : JSON.stringify(body, null, 2));
}

function sendHtml(res, html) {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer'
  });
  res.end(html);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; if (data.length > 1024 * 64) req.destroy(); });
    req.on('end', () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const method = req.method.toUpperCase();

  // Log
  const ip = req.headers['fly-client-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '-';
  console.log('[REQ] ' + new Date().toISOString() + ' ' + method + ' ' + url.pathname + ' ip=' + ip + ' ua=' + (req.headers['user-agent'] || '-'));

  // CORS preflight
  if (method === 'OPTIONS') {
    return send(res, 204, '', {});
  }

  // Health
  if (method === 'GET' && url.pathname === '/health') {
    return send(res, 200, { status: 'ok', service: 'authzen-mcp-demo' });
  }

  // JWKS -- agent's public key, fetchable by any verifier
  if (method === 'GET' && url.pathname === '/.well-known/jwks.json') {
    return send(res, 200, { keys: [agentPublicJwk] });
  }
  if (method === 'GET' && url.pathname === '/jwks.json') {
    return send(res, 200, { keys: [agentPublicJwk] });
  }

  // AuthZEN PDP API -- POST /access/v1/evaluation
  if (method === 'POST' && url.pathname === '/access/v1/evaluation') {
    const body = await readBody(req);
    let payload;
    try { payload = JSON.parse(body); } catch (e) { return send(res, 400, { error: 'invalid_json' }); }
    const decision = authzenEvaluate(payload);
    return send(res, 200, decision);
  }

  // Demo helper: simulate an MCP tool call going through the PDP
  // Optional ?tamper=1 to simulate tampering after signing
  if (method === 'POST' && url.pathname === '/demo/tool-call') {
    const body = await readBody(req);
    let inbound;
    try { inbound = JSON.parse(body); } catch (e) { return send(res, 400, { error: 'invalid_json' }); }

    const tamper = !!inbound.tamper;
    const targetUri = inbound.target_uri || '/mcp';
    const mcpBody = JSON.stringify(inbound.mcp_request || {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'transfer_funds', arguments: { from: 'A', to: 'B', amount: 100 } }
    });

    const evaluationRequest = buildEvaluationRequest({
      method: 'POST',
      targetUri,
      body: mcpBody,
      tamper
    });
    const decision = authzenEvaluate(evaluationRequest);

    return send(res, 200, {
      mcp_request: JSON.parse(mcpBody),
      tampered_after_signing: tamper,
      authzen_request: evaluationRequest,
      authzen_response: decision
    });
  }

  // Demo helper: tamper test specifically
  if (method === 'POST' && url.pathname === '/demo/tamper-test') {
    const targetUri = '/mcp';
    const mcpBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'transfer_funds', arguments: { from: 'A', to: 'B', amount: 100 } }
    });

    const honest = authzenEvaluate(buildEvaluationRequest({ method: 'POST', targetUri, body: mcpBody, tamper: false }));
    const tampered = authzenEvaluate(buildEvaluationRequest({ method: 'POST', targetUri, body: mcpBody, tamper: true }));

    return send(res, 200, { honest, tampered });
  }

  // Static index page
  if (method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
      return sendHtml(res, html);
    } catch (e) {
      return send(res, 200, { service: 'authzen-mcp-demo', see: 'README.md' });
    }
  }

  send(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
  console.log('authzen-mcp-demo listening on ' + PORT);
  console.log('  Reference implementation -- not affiliated with the OpenID Foundation.');
  console.log('  Companion to the AuthZEN MCP Profile v0.1 discussion draft.');
  console.log('  (c) 2026 Raza Sharif, CyberSecAI Ltd');
});
