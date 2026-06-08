const express = require('express');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();

// داینامیک کردن پورت برای سرورهای واقعی
const PORT = process.env.PORT || 8080;

// کلیدهای امنیتی (تغییر نکرده‌اند تا اکانت‌ها سالم بمانند)
const JWT_SECRET = "ronin_core_secret_key_2026_secure";
const TRON_RPC = "https://api.trongrid.io";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

// آدرس‌های رسمی قرارداد تتر
const TRON_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const ETH_USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const BSC_USDT_CONTRACT = "0x55d398326f99059ff775485246999027b3197955";

// RPC های معتبر
const EVM_NETWORKS = {
    eth: { name: "Ethereum", rpc: "https://cloudflare-eth.com", symbol: "ETH", usdt: ETH_USDT_CONTRACT },
    bsc: { name: "BSC", rpc: "https://bsc-dataseed.binance.org", symbol: "BNB", usdt: BSC_USDT_CONTRACT },
    polygon: { name: "Polygon", rpc: "https://polygon-rpc.com", symbol: "MATIC", usdt: null }
};

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.text({ limit: '10mb' })); // پشتیبانی از متن خام برای وب‌هوک

// تنظیمات CORS و Header برای دسترسی آزاد از اینترنت (هدر key اضافه شد)
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, key");
    res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// اتصال به دیتابیس
const db = new sqlite3.Database(path.join(__dirname, 'ronin_platform.db'), (err) => {
    if (err) console.error("[DB ERROR] ", err.message);
    else console.log("[DB] Connected to SQLite Database Successfully.");
});

// ساختار جداول دیتابیس
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        api_key TEXT UNIQUE,
        created_at TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        search_query TEXT NOT NULL,
        search_type TEXT NOT NULL,
        detected_network TEXT,
        request_source TEXT,
        status TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS token_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network TEXT NOT NULL,
        token_symbol TEXT NOT NULL,
        contract_address TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS deposit_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network TEXT NOT NULL,
        token_symbol TEXT NOT NULL,
        min_deposit REAL NOT NULL,
        created_at TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id TEXT UNIQUE NOT NULL,
        search_query TEXT NOT NULL,
        network TEXT,
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_hash TEXT NOT NULL,
        sender TEXT NOT NULL,
        content TEXT NOT NULL,
        visibility TEXT NOT NULL,
        allowed_users TEXT,
        created_at TEXT NOT NULL
    )`);

    // جدول لیست سیاه (AML Blacklist)
    db.run(`CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL UNIQUE,
        entity_name TEXT NOT NULL,
        risk_category TEXT NOT NULL,
        created_at TEXT NOT NULL
    )`);
});

// توابع کمکی
function generateShortId(length = 8) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

function hexToBase58Check(hex) {
    if (!hex) return null;
    try {
        const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        const buffer = Buffer.from(hex, 'hex');

        const hash1 = crypto.createHash('sha256').update(buffer).digest();
        const hash2 = crypto.createHash('sha256').update(hash1).digest();
        const checksum = hash2.slice(0, 4);

        const fullBuffer = Buffer.concat([buffer, checksum]);

        let value = BigInt('0x' + fullBuffer.toString('hex'));
        let result = '';
        while (value > 0n) {
            const remainder = value % 58n;
            value = value / 58n;
            result = ALPHABET[Number(remainder)] + result;
        }

        for (let i = 0; i < fullBuffer.length && fullBuffer[i] === 0; i++) {
            result = ALPHABET[0] + result;
        }

        return result;
    } catch (e) { return hex; }
}

function authenticateJwt(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied: Missing Token" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Forbidden: Invalid or Expired Token" });
        req.user = user;
        next();
    });
}

// سیستم احراز هویت وب‌هوک بر اساس هدر جدید 'key'
function authenticateApiKey(req, res, next) {
    const apiKey = req.headers['key'];
    if (!apiKey) return res.status(401).json({ error: "Access Denied: Missing 'key' header" });

    db.get("SELECT id, username FROM users WHERE api_key = ?", [apiKey], (err, user) => {
        if (err || !user) return res.status(403).json({ error: "Unauthorized: Invalid API Key" });
        req.user = user;
        next();
    });
}

// بررسی آدرس در بلک‌لیست
function checkBlacklist(address) {
    return new Promise((resolve) => {
        if (!address) return resolve(null);
        db.get("SELECT entity_name, risk_category FROM blacklist WHERE address = ?", [address.trim().toLowerCase()], (err, row) => {
            resolve(row || null);
        });
    });
}

// ================= روت‌های احراز هویت =================
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    const secret_key = req.body.secret_key || req.body.secretKey || req.body.secret;
    const now = new Date().toISOString();
    const REQUIRED_KEY = "hs1ireZOvfdP7bL8x4fHWmM32wvP";

    if (!username || !password) return res.status(400).json({ error: "Username and password required." });
    if (secret_key !== REQUIRED_KEY) return res.status(403).json({ error: "CRITICAL: Invalid Secret Master Key." });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userUniqueApiKey = 'ronin_' + crypto.randomBytes(16).toString('hex');
        
        db.run(`INSERT INTO users (username, password, api_key, created_at) VALUES (?, ?, ?, ?)`, 
        [username, hashedPassword, userUniqueApiKey, now], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: "Username already exists." });
                return res.status(500).json({ error: "Database failure during registration." });
            }
            res.json({ success: true, message: "Operator node registered successfully." });
        });
    } catch { res.status(500).json({ error: "Internal server error." }); }
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required." });

    db.get(`SELECT id, username, password, api_key FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: "Database error." });
        if (!user) return res.status(401).json({ error: "Invalid username or password." });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: "Invalid username or password." });

        // توکن لاگین بدون تاریخ انقضا برای سرور (محدودیت 24h حذف شد)
        const sessionToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        res.json({ token: sessionToken, apiKey: user.api_key, username: user.username });
    });
});

app.get('/api/history/logs', authenticateJwt, (req, res) => {
    db.all("SELECT search_query, search_type, detected_network, request_source, status, timestamp FROM search_history WHERE user_id = ? ORDER BY id DESC",
    [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ total: rows.length, history: rows });
    });
});

// ================= وایت‌لیست =================
app.post('/api/whitelist', authenticateJwt, (req, res) => {
    const { network, token_symbol, contract_address } = req.body;
    if (!network || !token_symbol || !contract_address) return res.status(400).json({ error: "All fields are required." });
    db.run("INSERT INTO token_whitelist (network, token_symbol, contract_address, created_at) VALUES (?, ?, ?, ?)",
    [network.toUpperCase(), token_symbol.toUpperCase(), contract_address.trim().toLowerCase(), new Date().toISOString()], function(err) {
        if (err) return res.status(400).json({ error: "Address already whitelisted." });
        res.json({ success: true, message: "Asset whitelisted successfully." });
    });
});

app.get('/api/whitelist', authenticateJwt, (req, res) => {
    db.all("SELECT id, network, token_symbol, contract_address, created_at FROM token_whitelist ORDER BY id DESC", [], (err, rows) => res.json({ whitelist: rows || [] }));
});

app.delete('/api/whitelist/:id', authenticateJwt, (req, res) => {
    db.run("DELETE FROM token_whitelist WHERE id = ?", [req.params.id], () => res.json({ success: true }));
});

// ================= قوانین واریز =================
app.post('/api/deposit-rules', authenticateJwt, (req, res) => {
    const { network, token_symbol, min_deposit } = req.body;
    if (!network || !token_symbol || min_deposit === undefined) return res.status(400).json({ error: "Missing fields." });
    const net = network.trim().toUpperCase();
    const sym = token_symbol.trim().toUpperCase();
    const minDep = parseFloat(min_deposit);

    db.get("SELECT id FROM deposit_rules WHERE UPPER(network) = ? AND UPPER(token_symbol) = ?", [net, sym], (err, row) => {
        if (row) {
            db.run("UPDATE deposit_rules SET min_deposit = ? WHERE id = ?", [minDep, row.id], () => res.json({ message: "Rule updated." }));
        } else {
            db.run("INSERT INTO deposit_rules (network, token_symbol, min_deposit, created_at) VALUES (?, ?, ?, ?)", [net, sym, minDep, new Date().toISOString()], () => res.json({ message: "Rule created." }));
        }
    });
});

app.get('/api/deposit-rules', authenticateJwt, (req, res) => {
    db.all("SELECT * FROM deposit_rules ORDER BY id DESC", [], (err, rows) => res.json({ rules: rows || [] }));
});

app.delete('/api/deposit-rules/:id', authenticateJwt, (req, res) => {
    db.run("DELETE FROM deposit_rules WHERE id = ?", [req.params.id], () => res.json({ message: "Deleted." }));
});

// ================= لیست سیاه AML =================
app.post('/api/blacklist', authenticateJwt, (req, res) => {
    const { address, entity_name, risk_category } = req.body;
    if (!address || !entity_name || !risk_category) return res.status(400).json({ error: "Missing fields" });
    
    db.run("INSERT INTO blacklist (address, entity_name, risk_category, created_at) VALUES (?, ?, ?, ?)",
    [address.trim().toLowerCase(), entity_name.trim(), risk_category.toUpperCase(), new Date().toISOString()], function(err) {
        if (err) return res.status(400).json({ error: "Address is already in the blacklist." });
        res.json({ success: true, message: "Added to AML blacklist." });
    });
});

app.get('/api/blacklist', authenticateJwt, (req, res) => {
    db.all("SELECT * FROM blacklist ORDER BY id DESC", [], (err, rows) => res.json({ blacklist: rows || [] }));
});

app.delete('/api/blacklist/:id', authenticateJwt, (req, res) => {
    db.run("DELETE FROM blacklist WHERE id = ?", [req.params.id], () => res.json({ success: true }));
});

// ================= سیستم یادداشت‌گذاری تیمی (TEAM NOTES) =================
app.get('/api/users/list', authenticateJwt, (req, res) => {
    db.all("SELECT username FROM users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Database error" });
        res.json({ users: rows.map(r => r.username) });
    });
});

app.post('/api/notes', authenticateJwt, (req, res) => {
    const { target_hash, content } = req.body;
    if (!target_hash || !content) return res.status(400).json({ error: "Missing fields" });

    const sender = req.user.username;
    const mentionRegex = /@(\w+)/g;
    const mentions = [...content.matchAll(mentionRegex)].map(m => m[1].toLowerCase());
    
    let visibility = 'RESTRICTED';
    let allowed_users = [];
    
    if (mentions.length === 0 || mentions.includes('all')) {
        visibility = 'ALL';
    } else {
        allowed_users = mentions;
        if (!allowed_users.includes(sender.toLowerCase())) {
            allowed_users.push(sender.toLowerCase());
        }
    }
    
    const now = new Date().toISOString();
    db.run("INSERT INTO notes (target_hash, sender, content, visibility, allowed_users, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [target_hash, sender, content, visibility, JSON.stringify(allowed_users), now], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: "Note added" });
    });
});

app.get('/api/notes/:target', authenticateJwt, (req, res) => {
    const target = req.params.target;
    const currentUser = req.user.username.toLowerCase();
    
    db.all("SELECT * FROM notes WHERE target_hash = ? ORDER BY id ASC", [target], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const visibleNotes = rows.filter(row => {
            if (row.visibility === 'ALL') return true;
            try {
                const allowed = JSON.parse(row.allowed_users);
                return allowed.includes(currentUser);
            } catch(e) { return false; }
        });
        
        res.json({ notes: visibleNotes });
    });
});

// ================= توابع اسکن بلاکچین =================
function makeHttpRequest(url, method = 'GET', postData = null, headers = {}, timeout = 15000) {
    return new Promise((resolve) => {
        try {
            const urlObj = new URL(url);
            const defaultHeaders = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            };
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: method,
                headers: { ...defaultHeaders, ...headers },
                timeout: timeout
            };
            
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => { 
                    try { resolve(JSON.parse(data)); } catch { resolve(data); } 
                });
            });
            
            req.on('timeout', () => { req.destroy(); resolve(null); });
            req.on('error', (err) => { resolve(null); });
            
            if (postData) req.write(JSON.stringify(postData));
            req.end();
        } catch (err) { resolve(null); }
    });
}

function decodeRpcString(hex) {
    if (!hex || hex === '0x') return 'UNKNOWN';
    try {
        let cleanHex = hex.replace(/^0x/, '');
        if (cleanHex.length > 128) cleanHex = cleanHex.slice(128);
        return Buffer.from(cleanHex, 'hex').toString('utf8').replace(/\0/g, '').trim() || 'TOKEN';
    } catch { return 'TOKEN'; }
}

async function queryTokenMetadataFromServer(rpcUrl, contractAddress) {
    try {
        const symRes = await makeHttpRequest(rpcUrl, 'POST', { jsonrpc: "2.0", method: "eth_call", params: [{ to: contractAddress, data: "0x95d89b41" }, "latest"], id: 2 });
        const decRes = await makeHttpRequest(rpcUrl, 'POST', { jsonrpc: "2.0", method: "eth_call", params: [{ to: contractAddress, data: "0x313ce567" }, "latest"], id: 3 });
        const nameRes = await makeHttpRequest(rpcUrl, 'POST', { jsonrpc: "2.0", method: "eth_call", params: [{ to: contractAddress, data: "0x06fdde03" }, "latest"], id: 4 });
        return {
            symbol: symRes && symRes.result ? decodeRpcString(symRes.result) : "TOKEN",
            name: nameRes && nameRes.result ? decodeRpcString(nameRes.result) : "ERC20 Asset",
            decimals: decRes && decRes.result && decRes.result !== "0x" ? parseInt(decRes.result, 16) : 18
        };
    } catch { return { symbol: "TOKEN", name: "ERC20 Asset", decimals: 18 }; }
}

function verifyTokenAuthenticity(network, symbol, contractAddress) {
    return new Promise((resolve) => {
        if (!contractAddress) return resolve({ status: "VERIFIED", details: "Official native asset of the chain." });
        db.get("SELECT contract_address FROM token_whitelist WHERE UPPER(network) = ? AND UPPER(token_symbol) = ?",
        [network.toUpperCase(), symbol.toUpperCase()], (err, row) => {
            if (row && row.contract_address === contractAddress.trim().toLowerCase()) {
                resolve({ status: "VERIFIED", details: "Official whitelisted contract match. Safe to credit." });
            } else if (row) {
                resolve({ status: "FAKE_ASSET", details: `CRITICAL RISK: Token spoofing detected! Expected contract ${row.contract_address} but received ${contractAddress}` });
            } else {
                resolve({ status: "UNKNOWN", details: "Asset is not tracked or verified in the official local whitelist." });
            }
        });
    });
}

async function scanTxAcrossChains(txHash) {
    const cleanHash = txHash.trim();
    let networkName = null, status = "failed", blockHeight = 0, fromAddr = "0x0", toAddr = "0x0", isToContract = false;
    let transferType = "Native", tokenName = "Unknown Asset", tokenSymbol = "ETH", contractAddress = null, amount = "0", rawValue = "0", decimals = 18, methodId = "0x", methodName = "Transfer", memo = null;

    // بررسی Bitcoin
    if (!cleanHash.startsWith("0x") && /^[0-9a-fA-F]{64}$/.test(cleanHash)) {
        try {
            const btcTx = await makeHttpRequest(`https://blockstream.info/api/tx/${cleanHash}`);
            if (btcTx && btcTx.txid) {
                networkName = "BITCOIN";
                status = (btcTx.status && btcTx.status.confirmed) ? "success" : "pending";
                blockHeight = (btcTx.status && btcTx.status.block_height) || 0;
                fromAddr = btcTx.vin && btcTx.vin[0] && btcTx.vin[0].prevout ? btcTx.vin[0].prevout.scriptpubkey_address : "BTC_SENDER";

                if (btcTx.vout && btcTx.vout.length > 0) {
                    toAddr = btcTx.vout[0].scriptpubkey_address || "BTC_RECEIVER";
                    const satoshiValue = btcTx.vout[0].value || 0;
                    rawValue = satoshiValue.toString(); amount = (satoshiValue / 1e8).toString();
                }
                tokenSymbol = "BTC"; tokenName = "Bitcoin Native Coin"; decimals = 8; methodName = "UTXO Ingress Transaction";
                return await buildResponse();
            }
        } catch(e) {}
    }

    // بررسی TON
    if (!cleanHash.startsWith("0x") && /^[0-9a-fA-F]{64}$/.test(cleanHash) && !networkName) {
        try {
            const tonTx = await makeHttpRequest(`https://tonapi.io/v2/blockchain/transactions/${cleanHash}`);
            if (tonTx && tonTx.hash && !tonTx.error) {
                networkName = "TON"; status = tonTx.success ? "success" : "failed"; blockHeight = tonTx.block ? parseInt(tonTx.block.split(",")[1] || 0) : 0;
                fromAddr = tonTx.in_msg && tonTx.in_msg.source ? tonTx.in_msg.source.address : "TON_SENDER"; toAddr = tonTx.in_msg && tonTx.in_msg.destination ? tonTx.in_msg.destination.address : "TON_RECEIVER";
                if (tonTx.in_msg && tonTx.in_msg.decoded_body && tonTx.in_msg.decoded_body.text) memo = tonTx.in_msg.decoded_body.text;
                const valueNanoton = tonTx.in_msg && tonTx.in_msg.value ? tonTx.in_msg.value : 0; rawValue = valueNanoton.toString(); amount = (valueNanoton / 1e9).toString();
                tokenSymbol = "TON"; tokenName = "Ton Native Asset"; decimals = 9; methodName = memo ? "Transfer with Memo" : "Transfer";
                return await buildResponse();
            }
        } catch(e) {}
    }

    // بررسی EVM networks
    if (cleanHash.startsWith("0x") || /^[0-9a-fA-F]{64}$/.test(cleanHash)) {
        const evmHash = cleanHash.startsWith("0x") ? cleanHash : "0x" + cleanHash;
        for (const [key, net] of Object.entries(EVM_NETWORKS)) {
            try {
                const txRes = await makeHttpRequest(net.rpc, 'POST', { jsonrpc: "2.0", method: "eth_getTransactionByHash", params: [evmHash], id: 21 });
                if (txRes && txRes.result) {
                    networkName = net.name; tokenSymbol = net.symbol; tokenName = net.name;
                    fromAddr = txRes.result.from ? txRes.result.from.toLowerCase() : "UNKNOWN";
                    toAddr = txRes.result.to ? txRes.result.to.toLowerCase() : "UNKNOWN";
                    rawValue = txRes.result.value ? BigInt(txRes.result.value).toString() : "0";
                    amount = txRes.result.value ? (Number(BigInt(txRes.result.value)) / 1e18).toString() : "0";
                    blockHeight = txRes.result.blockNumber ? parseInt(txRes.result.blockNumber, 16) : 0;
                    
                    const inputData = txRes.result.input || "0x";
                    if (inputData !== "0x" && inputData !== "0x00") {
                        methodId = inputData.slice(0, 10).toLowerCase();
                        methodName = "Contract Call";
                        isToContract = true;
                        if (methodId === "0xa9059cbb" && inputData.length >= 138) {
                            transferType = "TOKEN_PENDING";
                            contractAddress = toAddr; methodName = "Token Transfer";
                            toAddr = "0x" + inputData.slice(34, 74).toLowerCase();
                            const tokenRawValue = BigInt("0x" + inputData.slice(74, 138));
                            rawValue = tokenRawValue.toString();
                            const tokenMeta = await queryTokenMetadataFromServer(net.rpc, contractAddress);
                            tokenSymbol = tokenMeta.symbol; tokenName = tokenMeta.name; decimals = tokenMeta.decimals;
                            amount = (Number(tokenRawValue) / Math.pow(10, decimals)).toString();
                        }
                    }
                    
                    const receiptRes = await makeHttpRequest(net.rpc, 'POST', { jsonrpc: "2.0", method: "eth_getTransactionReceipt", params: [evmHash], id: 22 });
                    if (receiptRes && receiptRes.result) {
                        status = parseInt(receiptRes.result.status, 16) === 1 ? "success" : "failed";
                        if (transferType !== "TOKEN_PENDING" && receiptRes.result.logs) {
                            for (const log of receiptRes.result.logs) {
                                if (log.topics && log.topics[0] === TRANSFER_TOPIC && log.topics.length >= 3) {
                                    transferType = "TOKEN_PENDING";
                                    contractAddress = log.address.toLowerCase();
                                    fromAddr = "0x" + log.topics[1].slice(26).toLowerCase();
                                    toAddr = "0x" + log.topics[2].slice(26).toLowerCase();
                                    const logData = log.data === "0x" ? 0n : BigInt(log.data);
                                    rawValue = logData.toString();
                                    const tokenMeta = await queryTokenMetadataFromServer(net.rpc, contractAddress);
                                    tokenSymbol = tokenMeta.symbol; tokenName = tokenMeta.name; decimals = tokenMeta.decimals;
                                    amount = (Number(logData) / Math.pow(10, decimals)).toString();
                                    methodName = "Token Transfer"; isToContract = true;
                                    break;
                                }
                            }
                        }
                    }
                    return await buildResponse();
                }
            } catch(e) {}
        }
    }

    // بررسی TRON
    const tronHash = cleanHash.startsWith("0x") ? cleanHash.substring(2) : cleanHash;
    if (/^[0-9a-fA-F]{64}$/.test(tronHash) && !networkName) {
        try {
            const tronTx = await makeHttpRequest(`${TRON_RPC}/wallet/gettransactionbyid`, 'POST', { value: tronHash });
            if (tronTx && tronTx.txID) {
                networkName = "TRON"; status = "success";
                const contractWrapper = tronTx.raw_data.contract[0];
                const parameter = contractWrapper.parameter.value;

                fromAddr = hexToBase58Check(parameter.owner_address) || "TRON_SENDER";
                toAddr = hexToBase58Check(parameter.to_address) || "TRON_RECEIVER";
                rawValue = parameter.amount ? parameter.amount.toString() : "0";
                amount = parameter.amount ? (parameter.amount / 1e6).toString() : "0";
                tokenSymbol = "TRX"; tokenName = "Tron Native Asset"; decimals = 6; transferType = "Native";

                if (contractWrapper.type === "TriggerSmartContract") {
                    transferType = "TRC20"; isToContract = true; methodName = "Token Transfer"; methodId = "0xa9059cbb";
                    contractAddress = hexToBase58Check(parameter.contract_address) || null;
                    tokenSymbol = "USDT"; tokenName = "Tether USD"; decimals = 6;
                    if (parameter.data && parameter.data.startsWith("a9059cbb")) {
                        const targetHex = "41" + parameter.data.substring(32, 72);
                        toAddr = hexToBase58Check(targetHex);
                        const tokenRawValue = BigInt("0x" + parameter.data.substring(72));
                        rawValue = tokenRawValue.toString(); amount = (Number(tokenRawValue) / 1e6).toString();
                    }
                }
                return await buildResponse();
            }
        } catch(e) {}
    }

    if (!networkName) return null;

    async function buildResponse() {
        const authResult = await verifyTokenAuthenticity(networkName, tokenSymbol, contractAddress);
        const amlCheck = await checkBlacklist(fromAddr);
        
        const complianceRule = await new Promise((resObj) => {
            db.get("SELECT min_deposit FROM deposit_rules WHERE UPPER(network) = ? AND UPPER(token_symbol) = ?",
                [networkName.toUpperCase(), tokenSymbol.toUpperCase()], (err, row) => resObj(row));
        });

        const minRequired = complianceRule ? complianceRule.min_deposit : 0;
        const userAmount = parseFloat(amount);
        const isAuthentic = (authResult.status === 'VERIFIED' || contractAddress === null);
        const isAmountValid = userAmount >= minRequired;

        let isValidDeposit = true;
        let depositStatus = "CREDIT_ALLOWED: Transaction successfully verified and conforms to requirements.";

        // بررسی اولویت‌های امنیتی و AML
        if (amlCheck) {
            isValidDeposit = false;
            depositStatus = `REJECTED_AML_POLICY: Deposit originated from an unapproved entity (${amlCheck.entity_name} - ${amlCheck.risk_category}).`;
        } else if (!isAuthentic) {
            isValidDeposit = false;
            if (authResult.status === "FAKE_ASSET") depositStatus = "SECURITY_ALERT_FAILED: FAKE_ASSET_DETECTED - Contract address mismatch!";
            else depositStatus = "SECURITY_ALERT_FAILED: UNKNOWN_ASSET - Asset is not whitelisted on this exchange.";
        } else if (!isAmountValid) {
            isValidDeposit = false;
            depositStatus = `DEPOSIT_REJECTED: UNDER_MINIMUM_REQUIRED - Amount is less than ${minRequired} ${tokenSymbol}.`;
        }

        if (networkName === "TON" && !memo) {
            isValidDeposit = false;
            depositStatus = "DEPOSIT_REJECTED: MEMO_MISSING - Destination memo identifier is mandatory for TON deposits.";
        }

        let finalTransferType = transferType;
        if (transferType === "TOKEN_PENDING" || transferType === "ERC20") {
            finalTransferType = networkName.toUpperCase() === "BSC" ? "BEP20" : "ERC20";
        }

        return {
            "transaction_info": { "hash": txHash, "network": networkName, "status": status, "block_height": blockHeight, "timestamp": new Date().toISOString(), "confirmations": blockHeight > 0 ? 12 : 0 },
            "address_details": { "from": fromAddr, "to": toAddr, "is_to_contract": isToContract },
            "asset_transfer": { "type": finalTransferType, "token_name": tokenName, "token_symbol": tokenSymbol, "contract_address": contractAddress, "amount": amount, "raw_value": rawValue, "decimals": decimals },
            "metadata": { "memo": memo, "memo_type": memo ? "string" : null, "method_id": methodId, "method_name": methodName },
            "authenticity_check": authResult,
            "aml_origin_check": amlCheck ? { is_flagged: true, entity: amlCheck.entity_name, category: amlCheck.risk_category } : { is_flagged: false },
            "deposit_compliance": {
                "is_valid_deposit": isValidDeposit,
                "exchange_minimum_required": minRequired,
                "user_deposited_amount": userAmount,
                "status": depositStatus
            },
            "financials": { "fee_native": "0.0012", "fee_usd": "0.00", "gas_price_gwei": 0 }
        };
    }
}

async function scanAddressAcrossChains(address) {
    const cleanAddress = address.trim();
    let addressType = "eoa", nativeBalance = "0 ETH", activeNetwork = null, found = false;
    let isFlagged = false, tags = [];
    const amlCheck = await checkBlacklist(cleanAddress);

    if (/^0x[a-fA-F0-9]{40}$/.test(cleanAddress)) {
        for (const [key, net] of Object.entries(EVM_NETWORKS)) {
            try {
                const balRes = await makeHttpRequest(net.rpc, 'POST', { jsonrpc: "2.0", method: "eth_getBalance", params: [cleanAddress, "latest"], id: 13 });
                if (balRes && balRes.result) {
                    found = true; activeNetwork = net.name;
                    const value = (Number(BigInt(balRes.result)) / 1e18).toFixed(6);
                    nativeBalance = `${value} ${net.symbol}`;
                    tags.push(net.name);

                    const codeRes = await makeHttpRequest(net.rpc, 'POST', { jsonrpc: "2.0", method: "eth_getCode", params: [cleanAddress, "latest"], id: 11 });
                    if (codeRes && codeRes.result && codeRes.result !== "0x") addressType = "contract";
                    break;
                }
            } catch {}
        }
    }
    else if (cleanAddress.startsWith('T') && cleanAddress.length === 34) {
        try {
            const tronRes = await makeHttpRequest(`${TRON_RPC}/wallet/getaccount`, 'POST', { address: cleanAddress });
            if (tronRes) {
                found = true; activeNetwork = "TRON";
                addressType = tronRes.type === "Contract" ? "contract" : "eoa";
                nativeBalance = `${((tronRes.balance || 0) / 1e6).toFixed(4)} TRX`;
            }
        } catch {}
        if (!found) { found = true; activeNetwork = "TRON"; addressType = "eoa"; nativeBalance = "0.0000 TRX"; }
        tags.push("TRON");
    }
    else if (/^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(cleanAddress)) {
        try {
            const btcRes = await makeHttpRequest(`https://blockstream.info/api/address/${cleanAddress}`);
            if (btcRes && btcRes.address) {
                found = true; activeNetwork = "BITCOIN"; addressType = "eoa"; tags.push("BITCOIN");
                const funded = btcRes.chain_stats.funded_txo_sum || 0;
                const spent = btcRes.chain_stats.spent_txo_sum || 0;
                nativeBalance = `${((funded - spent) / 1e8).toFixed(8)} BTC`;
            }
        } catch {}
    }

    if (!found || !activeNetwork) return null;
    return {
        "address_profile": {
            "address": cleanAddress,
            "network": activeNetwork,
            "address_type": addressType,
            "ens_domain": null,
            "last_active": new Date().toISOString()
        },
        "balances": { "native_balance": nativeBalance, "native_balance_usd": "0.00" },
        "aml_origin_check": amlCheck ? { is_flagged: true, entity: amlCheck.entity_name, category: amlCheck.risk_category } : { is_flagged: false },
        "risk_scoring": { "is_flagged": isFlagged, "tags": tags }
    };
}

// ================= روت اصلی وب‌هوک و تولید رسید (نسخه استخراج هوشمند) =================
app.post('/api/v1/webhook', authenticateApiKey, async (req, res) => {
    let inputTarget = null;
    let requestSource = "API";

    // استخراج هوشمند اطلاعات (Smart Payload Extraction)
    if (typeof req.body === 'string' && req.body.trim().length > 0) {
        inputTarget = req.body.trim();
    } else if (req.body && typeof req.body === 'object') {
        // جستجوی اولویت‌دار: اول data، بعد tx_hash یا address
        inputTarget = req.body.data || req.body.tx_hash || req.body.address;
        
        // اگر هیچ کلید استانداردی نبود، اولین مقدار متنی طولانی رو برمی‌داره
        if (!inputTarget) {
            const values = Object.values(req.body);
            inputTarget = values.find(v => typeof v === 'string' && v.length >= 30);
        }
        
        if (req.body.source === "web_console") requestSource = "WEB";
    }

    if (!inputTarget) {
        return res.status(400).json({ error: "Invalid parameters. Please send a raw hash/address or use the 'data' key in JSON format." });
    }

    const cleanInput = inputTarget.trim();
    const now = new Date().toISOString();
    let data = null;
    let searchType = "";

    try {
        // تشخیص نوع ورودی
        const isEvmAddress = /^0x[a-fA-F0-9]{40}$/.test(cleanInput);
        const isTronAddress = /^T[a-zA-Z1-9]{33}$/.test(cleanInput);
        const isBtcAddress = /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(cleanInput);

        if (isEvmAddress || isTronAddress || isBtcAddress || cleanInput.length <= 62) {
            searchType = "ADDRESS";
            data = await scanAddressAcrossChains(cleanInput);
        } else {
            searchType = "TX_HASH";
            data = await scanTxAcrossChains(cleanInput);
        }

        const finalStatus = data ? "SUCCESS" : "NOT_FOUND";
        const netName = data ? (data.transaction_info ? data.transaction_info.network : data.address_profile.network) : "NONE";

        // ثبت تاریخچه جستجو
        db.run("INSERT INTO search_history (user_id, search_query, search_type, detected_network, request_source, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
            [req.user.id, cleanInput, searchType, netName, requestSource, finalStatus, now]);

        // تولید شناسه یکتا و ساخت رسید
        if (data) {
            const receiptId = generateShortId(8);
            data.receipt_id = receiptId; 

            db.run("INSERT INTO receipts (receipt_id, search_query, network, result_json, created_at) VALUES (?, ?, ?, ?, ?)",
                [receiptId, cleanInput, netName, JSON.stringify(data), now]);
        }

        return res.json(data || { error: "Target not found in ledger block history" });
        
    } catch (error) {
        console.error(`[API Error] ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// API پابلیک و عمومی برای دریافت اطلاعات رسید
app.get('/api/receipt/:id', (req, res) => {
    const receiptId = req.params.id;
    db.get("SELECT result_json, created_at FROM receipts WHERE receipt_id = ?", [receiptId], (err, row) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!row) return res.status(404).json({ error: "Receipt not found or expired" });
        
        res.json({ 
            receipt_id: receiptId, 
            created_at: row.created_at, 
            data: JSON.parse(row.result_json) 
        });
    });
});

// ================= تنظیمات مسیرها (Routing) =================
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/portal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/tx/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'receipt.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// بایند شدن به 0.0.0.0 برای دسترسی پابلیک در اینترنت
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CORE] Server running on port ${PORT}`);
    console.log(`[CORE] Supported networks: Ethereum, BSC, Polygon, Bitcoin, TRON, TON`);
});