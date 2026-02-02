const http = require('http');

function request(path, method, body) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, body: JSON.parse(data) });
                } catch (e) {
                    resolve({ status: res.statusCode, body: data });
                }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function run() {
    console.log('--- Testing Auth Flow ---');

    const username = 'testuser_' + Math.floor(Math.random() * 1000);
    const password = 'password123';

    // 1. Register
    console.log(`1. Registering ${username}...`);
    const regRes = await request('/auth/register', 'POST', { username, password });
    console.log('Register Response:', regRes.status, regRes.body);

    if (regRes.status !== 200) {
        console.error('Register failed');
        return;
    }

    // 2. Login
    console.log(`2. Logging in...`);
    const loginRes = await request('/auth/login', 'POST', { username, password });
    console.log('Login Response:', loginRes.status, loginRes.body);

    if (loginRes.status === 200 && loginRes.body.token) {
        console.log('SUCCESS: Token received:', loginRes.body.token);
    } else {
        console.error('Login failed');
    }
}

// Check if server is running? The script assumes it is.
// I will run the server in background first.
run();
