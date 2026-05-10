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

console.log('agent-directory worker unit tests passed');
