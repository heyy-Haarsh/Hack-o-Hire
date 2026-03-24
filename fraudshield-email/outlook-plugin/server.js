// outlook-plugin/server.js
// HTTPS server for Outlook add-in with API proxy
// Routes: /api/* → email API (HTTPS 8001), /voice/* → voice API (HTTP 8000)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ── SSL certificates ───────────────────────────────────────────────
const certDir = path.join(os.homedir(), '.office-addin-dev-certs');
const keyPath = path.join(certDir, 'localhost.key');
const certPath = path.join(certDir, 'localhost.crt');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.error('SSL certificates not found at:', certDir);
    console.error('Run: npx office-addin-dev-certs install');
    process.exit(1);
}

const sslOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
};

// ── Content types ──────────────────────────────────────────────────
const CONTENT_TYPES = {
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.html': 'text/html',
    '.xml': 'application/xml'
};

// ── Generic proxy function ─────────────────────────────────────────
// useHttps = true for email API (8001), false for voice API (8000)
function proxyRequest(req, res, targetPort, targetPath, useHttps) {
    const transport = useHttps ? https : http;
    const contentType = req.headers['content-type'] || '';
    const isMultipart = contentType.includes('multipart/form-data');

    if (isMultipart) {
        // Pipe raw body — needed for audio file uploads
        const proxyOptions = {
            hostname: 'localhost',
            port: targetPort,
            path: targetPath,
            method: req.method,
            headers: Object.assign({}, req.headers, {
                host: `localhost:${targetPort}`
            }),
            rejectUnauthorized: false
        };

        const proxyReq = transport.request(proxyOptions, proxyRes => {
            res.writeHead(proxyRes.statusCode, {
                'Content-Type': proxyRes.headers['content-type'] || 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            proxyRes.pipe(res);
        });

        proxyReq.on('error', err => {
            console.error(`[PROXY ERROR → :${targetPort}]`, err.message);
            res.writeHead(503);
            res.end(JSON.stringify({
                error: `Service on port ${targetPort} not reachable`,
                detail: err.message
            }));
        });

        req.pipe(proxyReq);
        return;
    }

    // JSON requests — buffer body first
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
        const proxyOptions = {
            hostname: 'localhost',
            port: targetPort,
            path: targetPath,
            method: req.method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body || '')
            },
            rejectUnauthorized: false
        };

        const proxyReq = transport.request(proxyOptions, proxyRes => {
            res.writeHead(proxyRes.statusCode, {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            proxyRes.pipe(res);
        });

        proxyReq.on('error', err => {
            console.error(`[PROXY ERROR → :${targetPort}]`, err.message);
            res.writeHead(503);
            res.end(JSON.stringify({
                error: `Service on port ${targetPort} not reachable`,
                detail: err.message,
                hint: targetPort === 8001
                    ? 'Start: cd fraudshield-email/src && python api.py'
                    : targetPort === 8000
                        ? 'Start: cd fraudshield-voice/src && python api.py'
                        : 'Start: cd Credential_Scanner-main && python main.py'
            }));
        });

        if (body) proxyReq.write(body);
        proxyReq.end();
    });
}

// ── HTTPS server ───────────────────────────────────────────────────
https.createServer(sslOptions, (req, res) => {
    console.log(`[${req.method}] ${req.url}`);

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const cleanUrl = req.url.split('?')[0];

    // ── /api/* → Email API — HTTPS port 8001 ───────────────────
    if (cleanUrl.startsWith('/api/')) {
        const targetPath = cleanUrl.replace('/api', '');
        console.log(`  → Email API (https:8001) ${targetPath}`);
        proxyRequest(req, res, 8001, targetPath, true);
        return;
    }

    // ── /voice/* → Voice API — HTTP port 8000 ──────────────────
    if (cleanUrl.startsWith('/voice/')) {
        const targetPath = cleanUrl.replace('/voice', '');
        console.log(`  → Voice API (http:8000) ${targetPath}`);
        proxyRequest(req, res, 8000, targetPath, false);
        return;
    }

    // ── /credential/* → Credential Scanner — HTTP port 8002 ────
    if (cleanUrl.startsWith('/credential/')) {
        const targetPath = cleanUrl;
        console.log(`  → Credential Scanner (http:8002) ${targetPath}`);
        proxyRequest(req, res, 8002, targetPath, false);
        return;
    }

    if (cleanUrl.startsWith('/guard/')) {
        const targetPath = '/guard/' + cleanUrl.slice('/guard/'.length);
        console.log(`  → Prompt Guard (http:8005) ${targetPath}`);
        proxyRequest(req, res, 8005, targetPath, false);
        return;
    }

    // ── Static files ────────────────────────────────────────────
    let filePath = '.' + cleanUrl;
    if (filePath === './') filePath = './taskpane.html';

    const ext = path.extname(filePath);
    const mimeType = CONTENT_TYPES[ext] || 'text/html';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            console.error('[404]', filePath);
            res.writeHead(404);
            res.end('File not found: ' + filePath);
        } else {
            res.writeHead(200, {
                'Content-Type': mimeType,
                'Access-Control-Allow-Origin': '*'
            });
            res.end(content, 'utf-8');
        }
    });

}).listen(3000, () => {
    console.log('');
    console.log('FraudShield Outlook Plugin server running');
    console.log('  Plugin  : https://localhost:3000/taskpane.html');
    console.log('  Email   : https://localhost:3000/api/   → https://localhost:8001/');
    console.log('  Voice   : https://localhost:3000/voice/ → http://localhost:8000/');
    console.log('');
    console.log('Required services:');
    console.log('  Email API : cd fraudshield-email/src  && python api.py');
    console.log('  Voice API : cd fraudshield-voice/src  && python api.py');
    console.log('');
});
