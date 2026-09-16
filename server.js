const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(ROOT, 'users.json');
const ONLINE_WINDOW_MS = 120000;

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.jfif': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.svg': 'image/svg+xml',
    '.mp3': 'audio/mpeg',
    '.mp4': 'audio/mp4',
    '.ogg': 'audio/ogg',
    '.wav': 'audio/wav',
};

let usersCache = null;
let dbPool = null;
let dbWriteChain = Promise.resolve();

function readUsersFileSync() {
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch (e) {
        return {};
    }
}

function loadUsers() {
    if (usersCache) return usersCache;
    usersCache = readUsersFileSync();
    return usersCache;
}

function saveUsers(users) {
    usersCache = users;
    if (dbPool) {
        const snapshot = JSON.stringify(users);
        dbWriteChain = dbWriteChain
            .catch(() => {})
            .then(() => dbPool.query(
                'INSERT INTO app_kv (k, v) VALUES (\'users\', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v',
                [snapshot]
            ));
        dbWriteChain.catch(e => console.error('DB save error:', e.message));
    } else {
        try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); } catch (e) {}
    }
}

async function persistToDb(users) {
    if (!dbPool) return;
    await dbPool.query(
        'INSERT INTO app_kv (k, v) VALUES (\'users\', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v',
        [JSON.stringify(users)]
    );
}

function saveChat(chat) {
    chatMessages = chat;
    if (dbPool) {
        const snapshot = JSON.stringify(chat);
        dbWriteChain = dbWriteChain
            .catch(() => {})
            .then(() => dbPool.query(
                'INSERT INTO app_kv (k, v) VALUES (\'chat\', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v',
                [snapshot]
            ));
        dbWriteChain.catch(e => console.error('DB chat save error:', e.message));
    }
}

async function initDatabase() {
    if (!process.env.DATABASE_URL) {
        console.log('Sin DATABASE_URL: los usuarios se guardan en users.json');
        return false;
    }
    const { Pool } = require('pg');
    dbPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    });
    await dbPool.query('CREATE TABLE IF NOT EXISTS app_kv (k text PRIMARY KEY, v text)');
    const res = await dbPool.query("SELECT v FROM app_kv WHERE k = 'users'");
    if (res.rows[0]) {
        try { usersCache = JSON.parse(res.rows[0].v); } catch (e) { usersCache = {}; }
    } else {
        usersCache = readUsersFileSync();
        await persistToDb(usersCache);
    }
    const chatRes = await dbPool.query("SELECT v FROM app_kv WHERE k = 'chat'");
    if (chatRes.rows[0]) {
        try { chatMessages = JSON.parse(chatRes.rows[0].v); } catch (e) { chatMessages = []; }
    }
    console.log('PostgreSQL conectado: ' + (Object.keys(usersCache).length) + ' usuarios cargados, ' + chatMessages.length + ' mensajes de chat');
    return true;
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => { data += chunk; });
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });
}

function sendJson(res, code, obj) {
    res.writeHead(code, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, x-token',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    });
    res.end(JSON.stringify(obj));
}

function hashPassword(password, salt) {
    return crypto.scryptSync(String(password), salt, 64).toString('hex');
}

function makeToken() {
    return crypto.randomBytes(32).toString('hex');
}

function validateCredentials(username, password) {
    if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return 'El nombre de usuario debe tener 3-20 caracteres (letras, números o _)';
    }
    if (typeof password !== 'string' || password.length < 4) {
        return 'La contraseña debe tener al menos 4 caracteres';
    }
    return null;
}

function handleAuth(req, res, mode) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { username, password } = parsed;
        const err = validateCredentials(username, password);
        if (err) return sendJson(res, 400, { error: err });

        const users = loadUsers();
        const normalized = username.toLowerCase();
        const existing = users[normalized];

        if (mode === 'register') {
            if (existing) return sendJson(res, 400, { error: 'Ese usuario ya existe' });
            const salt = crypto.randomBytes(16).toString('hex');
            const token = makeToken();
            users[normalized] = {
                username: username,
                salt: salt,
                hash: hashPassword(password, salt),
                token: token,
                data: {},
                lastSeen: Date.now(),
            };
            saveUsers(users);
            return sendJson(res, 200, { ok: true, token, username: username });
        } else {
            if (!existing) return sendJson(res, 401, { error: 'Usuario o contraseña incorrectos' });
            const hash = hashPassword(password, existing.salt);
            if (hash !== existing.hash) return sendJson(res, 401, { error: 'Usuario o contraseña incorrectos' });
            const token = makeToken();
            existing.token = token;
            existing.lastSeen = Date.now();
            saveUsers(users);
            return sendJson(res, 200, { ok: true, token, username: existing.username });
        }
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleLogout(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const token = parsed.token;
        if (token) {
            const users = loadUsers();
            let loggedOutKey = null;
            for (const key of Object.keys(users)) {
                if (users[key].token === token) {
                    users[key].token = null;
                    loggedOutKey = key;
                }
            }
            if (loggedOutKey) {
                saveUsers(users);
                for (const id in activeTrades) {
                    const tr = activeTrades[id];
                    if (String(tr.from).toLowerCase() === loggedOutKey || String(tr.to).toLowerCase() === loggedOutKey) {
                        cancelTrade(tr, 'desconectado');
                    }
                }
            }
        }
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleResetData(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const me = users[user.username.toLowerCase()];
        if (!me) return sendJson(res, 500, { error: 'Error interno' });
        me.data = {};
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function loadCodes() {
    try {
        const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'codes.json'), 'utf8'));
        return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    } catch (e) {
        return {};
    }
}

function handleCodeRedeem(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const code = String(parsed.code || '').trim().toUpperCase();
        if (!code) return sendJson(res, 400, { error: 'Escribe un código' });
        const codes = loadCodes();
        const entry = codes[code];
        if (!entry) return sendJson(res, 400, { error: 'Ese código no existe o ha caducado' });
        const users = loadUsers();
        const me = users[user.username.toLowerCase()];
        if (!me) return sendJson(res, 401, { error: 'Sesión inválida' });
        const redeemed = Array.isArray(me.redeemedCodes) ? me.redeemedCodes : [];
        if (redeemed.includes(code)) return sendJson(res, 400, { error: 'Ya has canjeado este código' });
        me.redeemedCodes = redeemed.concat(code);
        if (!me.data || typeof me.data !== 'object') me.data = {};
        const reward = { coins: 0, items: {} };
        if (typeof entry.coins === 'number' && Number.isFinite(entry.coins) && entry.coins > 0) {
            me.data.coins = (me.data.coins || 0) + Math.floor(entry.coins);
            me.data.totalCoins = (me.data.totalCoins || 0) + Math.floor(entry.coins);
            reward.coins = Math.floor(entry.coins);
        }
        if (entry.items && typeof entry.items === 'object') {
            if (!me.data.owned || typeof me.data.owned !== 'object') me.data.owned = {};
            for (const id in entry.items) {
                const qty = Math.max(1, Math.floor(Number(entry.items[id]) || 0));
                me.data.owned[id] = (me.data.owned[id] || 0) + qty;
                reward.items[id] = (reward.items[id] || 0) + qty;
            }
        }
        saveUsers(users);
        sendJson(res, 200, { ok: true, reward: reward });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

const DAILY_MAX_DAY = 31;
const DAILY_MS = 24 * 60 * 60 * 1000;

function loadNonRareItemIds() {
    try {
        const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'items.json'), 'utf8'));
        return (data.items || []).filter(i => i.chance <= 8000).map(i => i.id);
    } catch (e) {
        return [];
    }
}

function dailyNextDay(state, now) {
    if (!state || !state.last) return 1;
    const elapsed = now - state.last;
    if (elapsed >= DAILY_MS * 2) return 1;
    if (elapsed >= DAILY_MS) {
        const next = (state.streak || 0) + 1;
        return next > DAILY_MAX_DAY ? 1 : next;
    }
    return 0;
}

function dailyRewardForDay(day) {
    const reward = { coins: 0, items: {} };
    if (day >= DAILY_MAX_DAY) {
        reward.items.glitchedalba = 1;
        return reward;
    }
    const pool = loadNonRareItemIds();
    const itemChance = Math.min(45, 10 + day);
    if (Math.random() * 100 < itemChance && pool.length > 0) {
        const pick = pool[Math.floor(Math.random() * pool.length)];
        reward.items[pick] = 1;
    } else {
        reward.coins = Math.floor((60 + Math.random() * 140) * (1 + (day - 1) * 0.08));
    }
    return reward;
}

function handleDailyStatus(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const users = loadUsers();
    const me = users[user.username.toLowerCase()];
    if (!me) return sendJson(res, 500, { error: 'Error interno' });
    const now = Date.now();
    const day = dailyNextDay(me.dailyReward, now);
    sendJson(res, 200, { ok: true, canClaim: day > 0, day: day, claimed: day === 0 });
}

function handleDailyClaim(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const me = users[user.username.toLowerCase()];
        if (!me) return sendJson(res, 500, { error: 'Error interno' });
        const now = Date.now();
        const day = dailyNextDay(me.dailyReward, now);
        if (day === 0) return sendJson(res, 400, { error: 'Ya reclamaste hoy. Vuelve mañana' });
        const reward = dailyRewardForDay(day);
        if (!me.data || typeof me.data !== 'object') me.data = {};
        if (reward.coins > 0) {
            me.data.coins = (me.data.coins || 0) + reward.coins;
            me.data.totalCoins = (me.data.totalCoins || 0) + reward.coins;
        }
        for (const id in reward.items) {
            if (!me.data.owned || typeof me.data.owned !== 'object') me.data.owned = {};
            me.data.owned[id] = (me.data.owned[id] || 0) + reward.items[id];
        }
        me.dailyReward = { last: now, streak: day };
        saveUsers(users);
        sendJson(res, 200, { ok: true, day: day, reward: reward });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function findUserByToken(token) {
    if (!token) return null;
    const users = loadUsers();
    for (const key of Object.keys(users)) {
        if (users[key].token === token) return users[key];
    }
    return null;
}

function isOnline(user) {
    if (!user || !user.token) return false;
    return !!(user.lastSeen && (Date.now() - user.lastSeen < ONLINE_WINDOW_MS));
}

function handleHeartbeat(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const me = users[user.username.toLowerCase()];
        if (!me) return sendJson(res, 401, { error: 'Sesión inválida' });
        me.lastSeen = Date.now();
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

const ADMIN_ACCOUNT = 'ricardoadmin67';
const INFINITE_CAP = 999999999;

function handleLoad(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    if (user.username.toLowerCase() === ADMIN_ACCOUNT) {
        const owned = {};
        for (const id of loadItemIds()) owned[id] = INFINITE_CAP;
        return sendJson(res, 200, {
            ok: true, username: user.username,
            data: {
                rolls: (user.data && user.data.rolls) || 0,
                luck: 1,
                lucky: Object.keys(owned).length,
                owned: owned,
                coins: INFINITE_CAP,
                totalCoins: INFINITE_CAP,
                shop: { rollSpeed: 5, luckBoost: 10, coinMulti: 5 },
                autoSell: false,
            },
        });
    }
    sendJson(res, 200, { ok: true, username: user.username, data: user.data || {} });
}

function handleSave(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    readBody(req).then(body => {
        try {
            const parsed = JSON.parse(body || '{}');
            if (typeof parsed !== 'object' || parsed === null) throw new Error('bad data');
            user.data = parsed;
            const users = loadUsers();
            for (const key of Object.keys(users)) {
                if (users[key].token === user.token) {
                    users[key].data = parsed;
                    break;
                }
            }
            saveUsers(users);
            sendJson(res, 200, { ok: true });
        } catch (e) {
            sendJson(res, 400, { error: 'Datos inválidos' });
        }
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function findUserByName(username) {
    const users = loadUsers();
    return users[String(username || '').toLowerCase()] || null;
}

function loadItemIds() {
    try {
        const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'items.json'), 'utf8'));
        return new Set((data.items || []).map(i => i.id));
    } catch (e) {
        return new Set();
    }
}

function getItemChanceMap() {
    try {
        const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'items.json'), 'utf8'));
        const map = {};
        for (const i of (data.items || [])) map[i.id] = i.chance || 0;
        return map;
    } catch (e) {
        return {};
    }
}

function handleLeaderboard(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const users = loadUsers();
    const chances = getItemChanceMap();
    const rows = [];
    for (const key of Object.keys(users)) {
        const u = users[key];
        const owned = (u.data && u.data.owned) || {};
        let value = 0;
        const items = [];
        for (const id in owned) {
            const qty = owned[id];
            if (!qty || qty <= 0) continue;
            const ch = chances[id] || 0;
            value += ch * qty;
            items.push({ id: id, qty: qty, chance: ch });
        }
        if (items.length === 0) continue;
        items.sort((a, b) => b.chance - a.chance);
        rows.push({ username: u.username, value: Math.round(value), topItems: items.slice(0, 3) });
    }
    rows.sort((a, b) => b.value - a.value);
    sendJson(res, 200, { ok: true, rows: rows.slice(0, 30) });
}

function cleanupOwned(owned) {
    for (const key of Object.keys(owned)) {
        if (!owned[key] || owned[key] <= 0) delete owned[key];
    }
}

// ==================== Comercio v2 (estilo Adopt Me) ====================

let activeTrades = {};
const sseClients = {};

const CHAT_MAX = 100;
const CHAT_TTL_MS = 24 * 60 * 60 * 1000;
let chatMessages = [];
const chatSseClients = new Set();

function pruneChat() {
    const cutoff = Date.now() - CHAT_TTL_MS;
    chatMessages = chatMessages.filter(m => m && m.at && m.at >= cutoff);
    if (chatMessages.length > CHAT_MAX) chatMessages = chatMessages.slice(-CHAT_MAX);
    return chatMessages;
}

function pushChatToClients(obj) {
    const msg = 'data: ' + JSON.stringify(obj) + '\n\n';
    for (const conn of chatSseClients) {
        try { conn.res.write(msg); } catch (e) { chatSseClients.delete(conn); }
    }
}

function pushToUser(username, obj) {
    const key = String(username || '').toLowerCase();
    const conns = sseClients[key] || [];
    const msg = 'data: ' + JSON.stringify(obj) + '\n\n';
    for (const c of conns) {
        try { c.res.write(msg); } catch (e) {}
    }
}

function getTrade(username, statusMask) {
    const key = String(username || '').toLowerCase();
    for (const id in activeTrades) {
        const t = activeTrades[id];
        if (statusMask.indexOf(t.status) !== -1 &&
            (String(t.from).toLowerCase() === key || String(t.to).toLowerCase() === key)) {
            return t;
        }
    }
    return null;
}

function anyTradeOf(username) {
    return getTrade(username, ['pending', 'active']);
}

function cancelTrade(t, reason) {
    if (!activeTrades[t.id]) return;
    t.status = 'declined';
    delete activeTrades[t.id];
    pushToUser(t.from, { type: 'cancelled', reason: reason || '' });
    pushToUser(t.to, { type: 'cancelled', reason: reason || '' });
}

function completeTrade(t, fromU, toU, users) {
    const fOwned = (fromU.data && fromU.data.owned) || {};
    const tOwned = (toU.data && toU.data.owned) || {};
    let invalid = null;
    for (const item in t.offerFrom) {
        if ((fOwned[item] || 0) < t.offerFrom[item]) {
            invalid = `El jugador ${t.from} ya no tiene uno de los personajes ofrecidos`;
            break;
        }
    }
    if (!invalid) {
        for (const item in t.offerTo) {
            if ((tOwned[item] || 0) < t.offerTo[item]) {
                invalid = `El jugador ${t.to} ya no tiene uno de los personajes ofrecidos`;
                break;
            }
        }
    }
    if (invalid) {
        cancelTrade(t, invalid);
        return;
    }
    const fCoins = (fromU.data && typeof fromU.data.coins === 'number') ? fromU.data.coins : 0;
    const tCoins = (toU.data && typeof toU.data.coins === 'number') ? toU.data.coins : 0;
    const fOffered = t.coinsFrom || 0;
    const tOffered = t.coinsTo || 0;
    if (fOffered > fCoins || tOffered > tCoins) {
        cancelTrade(t, 'Uno de los jugadores ya no tiene suficientes monedas');
        return;
    }
    for (const item in t.offerFrom) {
        fOwned[item] = (fOwned[item] || 0) - t.offerFrom[item];
        tOwned[item] = (tOwned[item] || 0) + t.offerFrom[item];
    }
    for (const item in t.offerTo) {
        tOwned[item] = (tOwned[item] || 0) - t.offerTo[item];
        fOwned[item] = (fOwned[item] || 0) + t.offerTo[item];
    }
    cleanupOwned(fOwned);
    cleanupOwned(tOwned);
    fromU.data.owned = fOwned;
    toU.data.owned = tOwned;
    fromU.data.coins = fCoins - fOffered + tOffered;
    toU.data.coins = tCoins - tOffered + fOffered;
    saveUsers(users);
    t.status = 'completed';
    delete activeTrades[t.id];
    pushToUser(t.from, { type: 'completed', trade: t });
    pushToUser(t.to, { type: 'completed', trade: t });
}

function handleTradeStream(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || '';
    const user = findUserByToken(token);
    if (!user) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        return res.end('401');
    }
    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 3000\n\n');
    const key = user.username.toLowerCase();
    if (!sseClients[key]) sseClients[key] = [];
    const conn = { res };
    sseClients[key].push(conn);
    const t = anyTradeOf(user.username);
    if (t) {
        res.write('data: ' + JSON.stringify({ type: 'trade', trade: t }) + '\n\n');
    }
    const ping = setInterval(() => {
        try { res.write(': ping\n\n'); } catch (e) {}
    }, 25000);
    res.on('close', () => {
        clearInterval(ping);
        sseClients[key] = (sseClients[key] || []).filter(c => c !== conn);
        if (sseClients[key].length === 0) delete sseClients[key];
    });
}

function handleChatStream(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || '';
    const user = findUserByToken(token);
    if (!user) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        return res.end('401');
    }
    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 3000\n\n');
    const conn = { res };
    chatSseClients.add(conn);
    res.write('data: ' + JSON.stringify({ type: 'history', messages: pruneChat() }) + '\n\n');
    const ping = setInterval(() => {
        try { res.write(': ping\n\n'); } catch (e) {}
    }, 25000);
    res.on('close', () => {
        clearInterval(ping);
        chatSseClients.delete(conn);
    });
}

let chatLastSent = {};

function handleChatSend(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        if (!isOnline(user)) return sendJson(res, 403, { error: 'Solo los jugadores conectados al juego pueden escribir' });
        const text = String(parsed.text || '').trim();
        if (!text) return sendJson(res, 400, { error: 'Mensaje vacío' });
        if (text.length > 300) return sendJson(res, 400, { error: 'El mensaje es demasiado largo' });
        const users = loadUsers();
        const me = users[user.username.toLowerCase()];
        if (!me) return sendJson(res, 401, { error: 'Sesión inválida' });
        const key = user.username.toLowerCase();
        const now = Date.now();
        if (chatLastSent[key] && now - chatLastSent[key] < 1500) {
            return sendJson(res, 429, { error: 'Espera un momento antes de seguir escribiendo' });
        }
        chatLastSent[key] = now;
        pruneChat();
        chatMessages.push({ user: me.username, text: text, at: now });
        if (chatMessages.length > CHAT_MAX) chatMessages = chatMessages.slice(-CHAT_MAX);
        const message = chatMessages[chatMessages.length - 1];
        pushChatToClients({ type: 'msg', message: message });
        saveChat(chatMessages);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeOnline(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const list = [];
        for (const key of Object.keys(users)) {
            if (key === user.username.toLowerCase()) continue;
            if (!isOnline(users[key])) continue;
            list.push({ name: users[key].username, inTrade: !!anyTradeOf(users[key].username) });
        }
        sendJson(res, 200, { ok: true, users: list });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeRequest(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, to } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        if (anyTradeOf(user.username)) return sendJson(res, 400, { error: 'Ya tienes una solicitud pendiente o un trade activo' });
        const users = loadUsers();
        const from = users[user.username.toLowerCase()];
        const target = users[String(to || '').toLowerCase()];
        if (!target) return sendJson(res, 400, { error: 'No existe ese usuario' });
        if (target === from) return sendJson(res, 400, { error: 'No puedes comerciar contigo mismo' });
        if (!isOnline(target)) return sendJson(res, 400, { error: 'Ese jugador está desconectado' });
        if (anyTradeOf(target.username)) return sendJson(res, 400, { error: 'Ese jugador ya tiene una solicitud pendiente o un trade activo' });
        from.lastSeen = Date.now();
        saveUsers(users);
        const t = { id: makeToken(), from: from.username, to: target.username, status: 'pending', createdAt: Date.now(), coinsFrom: 0, coinsTo: 0 };
        activeTrades[t.id] = t;
        pushToUser(target.username, { type: 'request', trade: { id: t.id, from: t.from } });
        sendJson(res, 200, { ok: true, tradeId: t.id });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeRequests(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const incoming = [];
        const outgoing = [];
        for (const id in activeTrades) {
            const t = activeTrades[id];
            if (t.status !== 'pending') continue;
            if (String(t.to).toLowerCase() === user.username.toLowerCase()) incoming.push({ id: t.id, from: t.from, createdAt: t.createdAt });
            if (String(t.from).toLowerCase() === user.username.toLowerCase()) outgoing.push({ id: t.id, to: t.to, createdAt: t.createdAt });
        }
        sendJson(res, 200, { ok: true, incoming, outgoing });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeAccept(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, tradeId } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const t = activeTrades[tradeId];
        if (!t) return sendJson(res, 400, { error: 'Trade no encontrado o ya finalizado' });
        const meKey = user.username.toLowerCase();
        const isFrom = String(t.from).toLowerCase() === meKey;
        const isTo = String(t.to).toLowerCase() === meKey;
        if (!isFrom && !isTo) return sendJson(res, 400, { error: 'No formas parte de este trade' });

        if (t.status === 'pending') {
            if (!isTo) return sendJson(res, 400, { error: 'Aún no han aceptado tu solicitud' });
            const users = loadUsers();
            const from = users[t.from.toLowerCase()];
            if (!from || !isOnline(from)) {
                cancelTrade(t, 'desconectado');
                return sendJson(res, 400, { error: 'El jugador se ha desconectado' });
            }
            const toUser = users[t.to.toLowerCase()];
            if (!toUser) { delete activeTrades[tradeId]; return sendJson(res, 500, { error: 'Error interno' }); }
            toUser.lastSeen = Date.now();
            saveUsers(users);
            t.status = 'active';
            t.offerFrom = {};
            t.offerTo = {};
            t.coinsFrom = 0;
            t.coinsTo = 0;
            t.acceptFrom = false;
            t.acceptTo = false;
            pushToUser(t.from, { type: 'trade', trade: t });
            pushToUser(t.to, { type: 'trade', trade: t });
            return sendJson(res, 200, { ok: true, trade: t });
        }

        if (t.status === 'active') {
            const users = loadUsers();
            const fromU = users[t.from.toLowerCase()];
            const toU = users[t.to.toLowerCase()];
            if (!fromU || !toU || !isOnline(fromU) || !isOnline(toU)) {
                cancelTrade(t, 'desconectado');
                return sendJson(res, 400, { error: 'Uno de los jugadores se ha desconectado' });
            }
            if (isFrom) t.acceptFrom = !t.acceptFrom; else t.acceptTo = !t.acceptTo;
            if (t.acceptFrom && t.acceptTo) {
                completeTrade(t, fromU, toU, users);
                return sendJson(res, 200, { ok: true, done: true });
            }
            saveUsers(users);
            pushToUser(t.from, { type: 'trade', trade: t });
            pushToUser(t.to, { type: 'trade', trade: t });
            return sendJson(res, 200, { ok: true, trade: t });
        }

        return sendJson(res, 400, { error: 'Trade no válido' });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeOffer(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, tradeId, item, delta, coins } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const t = activeTrades[tradeId];
        if (!t || t.status !== 'active') return sendJson(res, 400, { error: 'El trade ya no está activo' });
        const meKey = user.username.toLowerCase();
        const isFrom = String(t.from).toLowerCase() === meKey;
        const isTo = String(t.to).toLowerCase() === meKey;
        if (!isFrom && !isTo) return sendJson(res, 400, { error: 'No formas parte de este trade' });
        const users = loadUsers();
        const u = users[meKey];
        if (!u) return sendJson(res, 401, { error: 'Sesión inválida' });

        if (coins !== undefined) {
            const c = parseInt(coins, 10);
            if (!Number.isInteger(c) || c < 0) return sendJson(res, 400, { error: 'Cantidad de monedas inválida' });
            const myCoins = (u.data && typeof u.data.coins === 'number') ? u.data.coins : 0;
            if (c > myCoins) return sendJson(res, 400, { error: 'No tienes tantas monedas' });
            if (isFrom) t.coinsFrom = c; else t.coinsTo = c;
            t.acceptFrom = false;
            t.acceptTo = false;
            u.lastSeen = Date.now();
            saveUsers(users);
            pushToUser(t.from, { type: 'trade', trade: t });
            pushToUser(t.to, { type: 'trade', trade: t });
            return sendJson(res, 200, { ok: true, trade: t });
        }

        const d = parseInt(delta, 10);
        if (!Number.isInteger(d) || (d !== 1 && d !== -1)) return sendJson(res, 400, { error: 'Acción inválida' });
        const offer = isFrom ? t.offerFrom : t.offerTo;
        const owned = (u.data && u.data.owned) || {};
        const cur = offer[item] || 0;
        const next = cur + d;
        if (next < 0) return sendJson(res, 400, { error: 'Cantidad inválida' });
        if (next > (owned[item] || 0)) return sendJson(res, 400, { error: 'No tienes tantos personajes' });
        if (next > 0 && cur === 0 && Object.keys(offer).length >= 4) return sendJson(res, 400, { error: 'Máximo 4 personajes por jugador' });
        if (next === 0) delete offer[item]; else offer[item] = next;
        t.acceptFrom = false;
        t.acceptTo = false;
        u.lastSeen = Date.now();
        saveUsers(users);
        pushToUser(t.from, { type: 'trade', trade: t });
        pushToUser(t.to, { type: 'trade', trade: t });
        sendJson(res, 200, { ok: true, trade: t });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeDecline(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, tradeId } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const t = activeTrades[tradeId];
        if (!t || t.status !== 'pending') return sendJson(res, 400, { error: 'Solicitud no encontrada' });
        if (String(t.to).toLowerCase() !== user.username.toLowerCase()) return sendJson(res, 400, { error: 'No puedes rechazar esto' });
        t.status = 'declined';
        delete activeTrades[tradeId];
        pushToUser(t.from, { type: 'declined', trade: t });
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeCancel(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, tradeId } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const t = activeTrades[tradeId];
        if (!t || (t.status !== 'pending' && t.status !== 'active')) return sendJson(res, 400, { error: 'Trade no encontrado o ya finalizado' });
        const meKey = user.username.toLowerCase();
        if (!(String(t.from).toLowerCase() === meKey || String(t.to).toLowerCase() === meKey)) return sendJson(res, 400, { error: 'No formas parte de este trade' });
        cancelTrade(t, '');
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

setInterval(() => {
    const users = loadUsers();
    const now = Date.now();
    for (const id in activeTrades) {
        const t = activeTrades[id];
        const a = users[t.from.toLowerCase()];
        const b = users[t.to.toLowerCase()];
        const aOk = a && a.token && now - (a.lastSeen || 0) < ONLINE_WINDOW_MS;
        const bOk = b && b.token && now - (b.lastSeen || 0) < ONLINE_WINDOW_MS;
        if (!aOk || !bOk) cancelTrade(t, 'desconectado');
    }
}, 15000);

const server = http.createServer((req, res) => {
    let urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    if (urlPath === '/') urlPath = '/index.html';

    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, x-token',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        });
        return res.end();
    }

    if (urlPath === '/api/music') {
        const musicDir = path.join(ROOT, 'music');
        fs.readdir(musicDir, (err, files) => {
            if (err) {
                return sendJson(res, 200, []);
            }
            const mp3s = files.filter(f => /\.(mp3|mp4|ogg|wav)$/i.test(f));
            sendJson(res, 200, mp3s);
        });
        return;
    }

    if (urlPath === '/api/register' && req.method === 'POST') {
        return handleAuth(req, res, 'register');
    }
    if (urlPath === '/api/login' && req.method === 'POST') {
        return handleAuth(req, res, 'login');
    }
if (urlPath === '/api/logout' && req.method === 'POST') {
                return handleLogout(req, res);
            }
            if (urlPath === '/api/reset-data' && req.method === 'POST') {
                return handleResetData(req, res);
            }
            if (urlPath === '/api/code/redeem' && req.method === 'POST') {
                return handleCodeRedeem(req, res);
            }
            if (urlPath === '/api/daily/status' && req.method === 'GET') {
                return handleDailyStatus(req, res);
            }
            if (urlPath === '/api/daily/claim' && req.method === 'POST') {
                return handleDailyClaim(req, res);
            }
    if (urlPath === '/api/heartbeat' && req.method === 'POST') {
        return handleHeartbeat(req, res);
    }
    if (urlPath === '/api/load' && req.method === 'GET') {
        return handleLoad(req, res);
    }
    if (urlPath === '/api/leaderboard' && req.method === 'GET') {
        return handleLeaderboard(req, res);
    }
    if (urlPath === '/api/save' && req.method === 'POST') {
        return handleSave(req, res);
    }
    if (urlPath === '/api/trade/stream' && req.method === 'GET') {
        return handleTradeStream(req, res);
    }
    if (urlPath === '/api/chat/stream' && req.method === 'GET') {
        return handleChatStream(req, res);
    }
    if (urlPath === '/api/chat/send' && req.method === 'POST') {
        return handleChatSend(req, res);
    }
    if (urlPath === '/api/trade/online' && req.method === 'POST') {
        return handleTradeOnline(req, res);
    }
    if (urlPath === '/api/trade/request' && req.method === 'POST') {
        return handleTradeRequest(req, res);
    }
    if (urlPath === '/api/trade/requests' && req.method === 'POST') {
        return handleTradeRequests(req, res);
    }
    if (urlPath === '/api/trade/accept' && req.method === 'POST') {
        return handleTradeAccept(req, res);
    }
    if (urlPath === '/api/trade/decline' && req.method === 'POST') {
        return handleTradeDecline(req, res);
    }
    if (urlPath === '/api/trade/offer' && req.method === 'POST') {
        return handleTradeOffer(req, res);
    }
    if (urlPath === '/api/trade/cancel' && req.method === 'POST') {
        return handleTradeCancel(req, res);
    }

    const filePath = path.join(ROOT, path.normalize(urlPath));
    if (!filePath.startsWith(ROOT)) {
        res.writeHead(403);
        return res.end('403');
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            return res.end('404 Not Found');
        }
        const ext = path.extname(filePath).toLowerCase();
        const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
        if (ext === '.html' || ext === '.js') headers['Cache-Control'] = 'no-store';
        res.writeHead(200, headers);
        res.end(data);
    });
});

initDatabase().then(() => {
    server.listen(PORT, () => {
        console.log(`Servidor corriendo en http://localhost:${PORT}`);
        console.log('Presiona Ctrl+C para detener');
    });
}).catch((e) => {
    console.error('Error inicializando la base de datos:', e.message);
    server.listen(PORT, () => {
        console.log(`Servidor corriendo en http://localhost:${PORT} (sin base de datos)`);
    });
});

setInterval(() => {
    const before = chatMessages.length;
    pruneChat();
    if (chatMessages.length !== before) saveChat(chatMessages);
}, 6 * 60 * 60 * 1000);