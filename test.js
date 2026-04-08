// Minimal smoke test for authzen-mcp-demo
// Run: node test.js (after starting the server with `node server.js`)

const http = require('http');

const PORT = process.env.PORT || 3300;
const HOST = process.env.HOST || '127.0.0.1';

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({ host: HOST, port: PORT, method, path, headers: { 'content-type': 'application/json', 'content-length': data ? Buffer.byteLength(data) : 0 } }, (res) => {
      let buf = '';
      res.on('data', (c) => buf += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); } catch (e) { resolve({ status: res.statusCode, body: buf }); } });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function assert(name, cond) {
  if (cond) { console.log('  PASS  ' + name); return true; }
  console.log('  FAIL  ' + name); failed++; return false;
}

let failed = 0;

(async () => {
  console.log('authzen-mcp-demo smoke test');
  console.log('---------------------------');

  console.log('1. health');
  const h = await request('GET', '/health');
  assert('health returns 200', h.status === 200);
  assert('health returns ok status', h.body.status === 'ok');

  console.log('2. jwks');
  const jwks = await request('GET', '/.well-known/jwks.json');
  assert('jwks returns 200', jwks.status === 200);
  assert('jwks has at least 1 key', jwks.body.keys && jwks.body.keys.length >= 1);
  assert('jwks key is ES256', jwks.body.keys[0].alg === 'ES256');

  console.log('3. honest request returns Permit');
  const honest = await request('POST', '/demo/tool-call', { tamper: false });
  assert('honest status 200', honest.status === 200);
  assert('honest decision is true', honest.body.authzen_response.decision === true);
  assert('honest signature_verified is true', honest.body.authzen_response.context.reason_admin.signature_verified === true);

  console.log('4. tampered request returns Deny');
  const tampered = await request('POST', '/demo/tool-call', { tamper: true });
  assert('tampered status 200', tampered.status === 200);
  assert('tampered decision is false', tampered.body.authzen_response.decision === false);
  assert('tampered signature_verified is false', tampered.body.authzen_response.context.reason_admin.signature_verified === false);

  console.log('5. AuthZEN PDP rejects request with no signature');
  const noSig = await request('POST', '/access/v1/evaluation', {
    subject: { type: 'agent', id: 'test', properties: {} },
    action: { name: 'tools/call' },
    resource: { type: 'mcp_tool', id: 'test' },
    context: {}
  });
  assert('no-sig returns 200', noSig.status === 200);
  assert('no-sig decision is false', noSig.body.decision === false);

  console.log('---------------------------');
  if (failed > 0) {
    console.log('FAILED: ' + failed + ' assertion(s)');
    process.exit(1);
  } else {
    console.log('ALL PASS');
  }
})().catch((e) => { console.error(e); process.exit(2); });
