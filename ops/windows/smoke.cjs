'use strict';
const WebSocket = require('ws');
const base = process.argv[2] || 'http://127.0.0.1:3000';
(async () => {
    for (const route of ['/health/live', '/health/ready']) {
        const res = await fetch(base + route, { signal: AbortSignal.timeout(15000) });
        const data = await res.json();
        if (!res.ok || (route.endsWith('ready') && data.status !== 'ready')) throw new Error('Health failed');
        console.log(route, res.status, data.commitSha || '', data.checks?.database?.migrationHead || '');
    }
    const cors = await fetch(base + '/health/live', { method: 'OPTIONS', headers: { Origin: 'https://www.talkx.chat', 'Access-Control-Request-Method': 'GET' }, signal: AbortSignal.timeout(10000) });
    if (cors.headers.get('access-control-allow-origin') !== 'https://www.talkx.chat') throw new Error('CORS failed');
    await new Promise((resolve, reject) => {
        const ws = new WebSocket(base.replace(/^http/, 'ws'), { origin: 'https://www.talkx.chat', handshakeTimeout: 10000 });
        ws.once('open', () => { ws.close(); resolve(); });
        ws.once('error', reject);
    });
    await new Promise((resolve, reject) => {
        const ws = new WebSocket(base.replace(/^http/, 'ws'), { origin: 'https://foreign.invalid', handshakeTimeout: 10000 });
        ws.once('open', () => { ws.close(); reject(new Error('Foreign WS Origin accepted')); });
        ws.once('unexpected-response', (request, response) => {
            response.resume(); request.destroy();
            if (response.statusCode === 401 || response.statusCode === 403) resolve();
            else reject(new Error('Unexpected foreign Origin response'));
        });
        ws.once('error', reject);
    });
    console.log('CORS, allowed WebSocket handshake, and foreign Origin rejection passed');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
