// MCP smoke test — spawns src/index.js over stdio, lists tools, creates a room,
// sends a message, polls it back, asserts ciphertext round-trip.

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'src', 'index.js');
const BASE = process.env.BASE || 'https://safebot.chat';

function jsonrpc(id, method, params) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
}

function startServer() {
  const p = spawn('node', [BIN], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, SAFEBOT_BASE: BASE },
  });
  p.stderr.on('data', (chunk) => process.stderr.write('[mcp stderr] ' + chunk));
  return p;
}

async function rpc(proc, id, method, params, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { proc.stdout.off('data', handler); reject(new Error(`rpc ${method} timeout`)); }, timeoutMs);
    let buf = '';
    function handler(chunk) {
      buf += chunk.toString();
      for (;;) {
        const nl = buf.indexOf('\n');
        if (nl === -1) break;
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let obj;
        try { obj = JSON.parse(line); } catch (_) { continue; }
        if (obj.id === id) {
          clearTimeout(timer);
          proc.stdout.off('data', handler);
          if (obj.error) reject(new Error(obj.error.message || JSON.stringify(obj.error)));
          else resolve(obj.result);
          return;
        }
      }
    }
    proc.stdout.on('data', handler);
    proc.stdin.write(jsonrpc(id, method, params));
  });
}

async function callTool(proc, id, name, args) {
  return rpc(proc, id, 'tools/call', { name, arguments: args });
}

function extractText(res) {
  if (!res || !res.content) return '';
  return res.content.filter((c) => c.type === 'text').map((c) => c.text).join('\n');
}

async function main() {
  console.log('▶︎ MCP smoke test against', BASE);
  const server = startServer();

  const failures = [];
  const expect = (cond, msg) => { if (!cond) { failures.push(msg); console.log('  ✗', msg); } else console.log('  ✓', msg); };

  // 1. Initialize
  await rpc(server, 1, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'smoke', version: '0.0.1' },
  });
  console.log('  ✓ initialize handshake');

  // 2. List tools
  const list = await rpc(server, 2, 'tools/list', {});
  const names = (list.tools || []).map((t) => t.name).sort();
  expect(names.length === 6, `tools/list returns 6 tools (got ${names.length})`);
  for (const wanted of ['create_room', 'send_message', 'wait_for_messages', 'get_transcript', 'room_status', 'next_task']) {
    expect(names.includes(wanted), `tool "${wanted}" is listed`);
  }

  // 3. create_room
  const r1 = await callTool(server, 3, 'create_room', {});
  const text1 = extractText(r1);
  const urlMatch = text1.match(/https?:\/\/[^\s]+#k=[A-Za-z0-9_-]+/);
  expect(!!urlMatch, 'create_room returns a URL with #k= fragment');
  const roomUrl = urlMatch ? urlMatch[0] : '';

  // 4. room_status on brand-new room (may be empty)
  const s1 = await callTool(server, 4, 'room_status', { url: roomUrl });
  expect(/Room\s+[A-Z0-9]+|does not currently exist/.test(extractText(s1)), 'room_status parses');

  // 5. send_message
  const sent = await callTool(server, 5, 'send_message', { url: roomUrl, text: 'smoke test hello', name: 'smoke-sender' });
  const sentText = extractText(sent);
  expect(/seq=\d+/.test(sentText), 'send_message returns a seq');

  // 6. wait_for_messages with include_self=true should see our own message.
  const got = await callTool(server, 6, 'wait_for_messages', {
    url: roomUrl,
    after_seq: 0,
    timeout_seconds: 5,
    include_self: true,
    name: 'smoke-sender',
  });
  const gotText = extractText(got);
  expect(gotText.includes('smoke test hello'), 'wait_for_messages round-trips the plaintext');

  // 7. get_transcript also sees it
  const tr = await callTool(server, 7, 'get_transcript', { url: roomUrl });
  expect(extractText(tr).includes('smoke test hello'), 'get_transcript round-trips the plaintext');

  // Clean up.
  server.kill('SIGTERM');
  await new Promise((r) => server.on('exit', r));

  if (failures.length) {
    console.log(`\n✗ ${failures.length} failure(s)`);
    process.exit(1);
  }
  console.log('\n✓ all MCP smoke checks passed');
}

main().catch((e) => { console.error('smoke crashed:', e); process.exit(2); });
