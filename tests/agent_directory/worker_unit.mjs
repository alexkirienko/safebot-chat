import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { internals } from '../../workers/agent-directory/src/index.js';

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function sign(text, keypair) {
  return b64(nacl.sign.detached(new TextEncoder().encode(text), keypair.secretKey));
}

const kp = nacl.sign.keyPair();
const now = Date.now();
const profile = internals.cleanProfile({
  handle: 'stage-agent',
  display_name: 'Stage Agent',
  framework: 'OpenClaw',
  summary: 'Finds Python and market-data peers.',
  capabilities: ['Python', 'Market Data', 'Python'],
  topics: ['Trading Research'],
  languages: ['en', 'ru'],
  updated_at: now,
  expires_at: now + 60_000,
}, 'stage-agent');

assert.equal(profile.handle, 'stage-agent');
assert.equal(profile.framework, 'openclaw');
assert.deepEqual(profile.capabilities, ['python', 'market-data']);

const signingText = await internals.profileSigningText(profile);
assert.ok(sign(signingText, kp).length > 80);
assert.equal(
  internals.canonicalize({ z: 1, a: ['x', { b: true }] }),
  '{"a":["x",{"b":true}],"z":1}',
);

assert.throws(() => internals.cleanProfile({
  updated_at: now,
  summary: 'join https://bot2bot.chat/room/ABCD#k=secret',
}, 'stage-agent'), /forbidden/);

assert.equal(internals.ftsQuery('Python market-data!!'), '"python"* AND "market-data"*');

const authKp = nacl.sign.keyPair();
const authBoxPub = b64(nacl.randomBytes(32));
const authSignPub = b64(authKp.publicKey);
const authPath = '/api/agents/stage-agent/heartbeat';
const authTs = Date.now();
const authNonce = 'nonce-' + Buffer.from(nacl.randomBytes(18)).toString('base64url');
const authText = `POST ${authPath} ${authTs} ${authNonce}`;
const authSig = sign(authText, authKp);
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(JSON.stringify({
  handle: 'stage-agent',
  box_pub: authBoxPub,
  sign_pub: authSignPub,
}), { status: 200, headers: { 'content-type': 'application/json' } });

internals.resetForTests();
const authReq = new Request(`https://directory.test${authPath}`, {
  method: 'POST',
  headers: { authorization: `Bot2Bot ts=${authTs},n=${authNonce},sig=${authSig}` },
});
assert.equal(await internals.verifyBot2BotAuth(authReq, { IDENTITY_BASE_URL: 'https://identity.test' }, 'stage-agent'), true);
assert.equal(await internals.verifyBot2BotAuth(authReq, { IDENTITY_BASE_URL: 'https://identity.test' }, 'stage-agent'), false);

const unpaddedSig = authSig.replace(/=+$/, '');
assert.equal(internals.isCanonicalBase64(authSig, 64), true);
assert.equal(internals.isCanonicalBase64(unpaddedSig, 64), false);
assert.equal(internals.verifySignature(authText, unpaddedSig, authSignPub), false);
assert.equal(internals.verifySignature(authText, authSig, authSignPub.replace(/=+$/, '')), false);

internals.resetForTests();
const rlReq = new Request('https://directory.test/api/agents?q=python', {
  headers: { 'cf-connecting-ip': '203.0.113.10' },
});
const rlEnv = { AGENT_DIRECTORY_SEARCH_RL_CAP: '2', AGENT_DIRECTORY_SEARCH_RL_REFILL_PER_SEC: '0.001' };
assert.equal(internals.rateLimitOk(rlReq, rlEnv, 'agents:search', 'search'), true);
assert.equal(internals.rateLimitOk(rlReq, rlEnv, 'agents:search', 'search'), true);
assert.equal(internals.rateLimitOk(rlReq, rlEnv, 'agents:search', 'search'), false);

globalThis.fetch = originalFetch;

console.log('agent-directory worker unit tests passed');
