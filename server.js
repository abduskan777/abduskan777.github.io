const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(ROOT, 'users.json');
const ONLINE_WINDOW_MS = 600000;

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
        'Access-Control-Allow-Headers': 'Content-Type, x-token, x-match',
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
                const pvpM = pvpMatchForKey(loggedOutKey);
                if (pvpM) {
                    const isC = String(pvpM.challenger.key) === loggedOutKey;
                    const offender = isC ? pvpM.challenger : pvpM.opponent;
                    const other = isC ? pvpM.opponent : pvpM.challenger;
                    if (pvpM.status === 'playing' && !pvpM.winner) {
                        pvpM.winner = other;
                        pvpM.reason = 'abandono';
                        addLogHelper(pvpM, `${offender.username} cerró sesión y abandona la partida`, 'system');
                        finalizeMatch(pvpM);
                        saveUsers(users);
                    } else if (pvpM.status === 'open' || pvpM.status === 'preparing') {
                        refundEscrow(users[pvpM.challenger.key], pvpM.challenger.escrow);
                        refundEscrow(users[pvpM.opponent.key], pvpM.opponent.escrow);
                        pvpM.challenger.escrow = { coins: 0, items: {} };
                        pvpM.opponent.escrow = { coins: 0, items: {} };
                        pvpM.status = 'cancelled';
                        pvpMatches.delete(pvpM.id);
                        saveUsers(users);
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
        const repeatable = entry.repeatable === true || entry.repeatable === 'always';
        if (!repeatable && redeemed.includes(code)) return sendJson(res, 400, { error: 'Ya has canjeado este código' });
        if (!repeatable) me.redeemedCodes = redeemed.concat(code);
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

const CASINO_MIN_BET = 20;
const CASINO_ITEM_ID = 'anderdingus';
const CASINO_RESULTS = ['red', 'black', 'green'];
const CASINO_PROBS = { green: 1 / 37, red: 18 / 37, black: 18 / 37 };

function casinoSpinColor() {
    const r = Math.random();
    if (r < CASINO_PROBS.green) return 'green';
    return r < CASINO_PROBS.green + CASINO_PROBS.red ? 'red' : 'black';
}

function handleCasinoSpin(req, res) {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
        try {
            const parsed = body ? JSON.parse(body) : {};
            const token = String(parsed.token || '');
            const color = String(parsed.color || '');
            const bet = Math.floor(Number(parsed.bet));
            const user = findUserByToken(token);
            if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
            if (CASINO_RESULTS.indexOf(color) === -1) return sendJson(res, 400, { error: 'Color inválido: rojo, negro o verde' });
            if (!Number.isFinite(bet) || bet < CASINO_MIN_BET) return sendJson(res, 400, { error: 'La apuesta mínima es 20' });

            const users = loadUsers();
            const me = users[user.username.toLowerCase()];
            if (!me) return sendJson(res, 401, { error: 'Sesión inválida' });
            me.data = me.data || {};
            me.data.coins = Number.isFinite(me.data.coins) ? me.data.coins : 0;
            if (bet > me.data.coins) return sendJson(res, 400, { error: 'Saldo insuficiente' });

            const result = casinoSpinColor();
            const won = result === color;
            const onChangeCoins = won ? (color === 'green' ? bet * 9 : bet) : -bet;

            me.data.coins = Math.max(0, me.data.coins + onChangeCoins);
            let itemId = null;
            if (won && color === 'green') {
                me.data.owned = me.data.owned || {};
                me.data.owned[CASINO_ITEM_ID] = (me.data.owned[CASINO_ITEM_ID] || 0) + 1;
                itemId = CASINO_ITEM_ID;
            }
            saveUsers(users);
            sendJson(res, 200, {
                ok: true,
                event: {
                    bet: bet,
                    color: color,
                    result: result,
                    won: won,
                    payout: won ? (color === 'green' ? bet * 10 : bet * 2) : 0,
                    itemId: itemId,
                },
                coins: me.data.coins,
            });
        } catch (e) {
            sendJson(res, 500, { error: 'Error interno' });
        }
    });
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

// ===================== PvP 1v1 =====================
const PVP_START_HP = 20;
const PVP_MAX_ENERGY = 10;
const PVP_START_ENERGY = 3;
const PVP_START_HAND = 4;
const PVP_MAX_HAND = 8;
const PVP_MAX_DECK = 8;
const PVP_MAX_FIELD = 3;
const PVP_TURN_ENERGY = 2;
const PVP_TIMEOUT_MS = 90000;
const PVP_CANCEL_MS = 120000;
const pvpMatches = new Map();
let pvpResultsLog = [];
const PVP_LOG_FILE = path.join(ROOT, 'pvp_log.json');

function savePvpLog() {
    if (dbPool) {
        const snapshot = JSON.stringify(pvpResultsLog);
        dbWriteChain = dbWriteChain
            .catch(() => {})
            .then(() => dbPool.query(
                'INSERT INTO app_kv (k, v) VALUES (\'pvp_log\', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v',
                [snapshot]
            ));
        dbWriteChain.catch(e => console.error('DB pvp log error:', e.message));
    } else {
        try { fs.writeFileSync(PVP_LOG_FILE, JSON.stringify(pvpResultsLog)); } catch (e) {}
    }
}

function loadPvpLogFromDb() {
    if (!dbPool) return;
    dbPool.query("SELECT v FROM app_kv WHERE k = 'pvp_log'").then(res => {
        if (res.rows[0]) {
            try { pvpResultsLog = JSON.parse(res.rows[0].v); } catch (e) { pvpResultsLog = []; }
        }
    }).catch(() => {});
}

function pvpTierIndex(chance) {
    const c = chance;
    if (c <= 16) return 0;
    if (c <= 128) return 1;
    if (c <= 8000) return 2;
    if (c <= 400000) return 3;
    if (c <= 10000000) return 4;
    return 5;
}

function cardForId(id) {
    const chanceMap = getItemChanceMap();
    const chance = chanceMap[id] || 100000;
    const r = pvpTierIndex(chance);
    return { id: id, atk: 1 + r * 2, hp: 4 + r * 5, cost: 1 + r };
}

function ownData(user) {
    if (!user.data || typeof user.data !== 'object') user.data = {};
    if (!user.data.owned || typeof user.data.owned !== 'object') user.data.owned = {};
    user.data.coins = Number(user.data.coins) || 0;
    if (Number.isNaN(user.data.totalCoins)) user.data.totalCoins = user.data.coins;
    return user.data;
}

function pvpMatchForKey(key) {
    for (const m of pvpMatches.values()) {
        if (String(m.challenger.key) === key || String(m.opponent.key) === key) return m;
    }
    return null;
}

function pvpHasBet(username) {
    const key = String(username).toLowerCase();
    for (const m of pvpMatches.values()) {
        if (m.status === 'finished' || m.status === 'cancelled') continue;
        if (String(m.challenger.key) === key && m.challenger.escrow) {
            if (m.challenger.escrow.coins > 0 || Object.keys(m.challenger.escrow.items || {}).length) return true;
        }
        if (String(m.opponent.key) === key && m.opponent.escrow) {
            if (m.opponent.escrow.coins > 0 || Object.keys(m.opponent.escrow.items || {}).length) return true;
        }
    }
    return false;
}

function escrowSize(escrow) {
    if (!escrow) return { coins: 0, items: {} };
    const items = {};
    for (const id in (escrow.items || {})) if (escrow.items[id] > 0) items[id] = escrow.items[id];
    return { coins: escrow.coins || 0, items: items };
}

function addWinningsToUser(user, escrow) {
    const data = ownData(user);
    data.coins += escrow.coins || 0;
    data.totalCoins += escrow.coins || 0;
    for (const id in (escrow.items || {})) {
        if (escrow.items[id] > 0) data.owned[id] = (data.owned[id] || 0) + escrow.items[id];
    }
    return escrow;
}

function addLogHelper(m, msg, type, data) {
    m.log.push({ t: Date.now(), s: type || 'info', msg: msg, data: data || {} });
    if (m.log.length > 120) m.log.splice(0, m.log.length - 120);
}

function validateBet(user, bet, users) {
    const data = ownData(user);
    let coins = 0;
    let item = null;
    if (bet && typeof bet === 'object') {
        if (bet.coins !== undefined && bet.coins !== null) {
            coins = Math.floor(Number(bet.coins) || 0);
            if (coins < 0) coins = 0;
        }
        if (bet.item && bet.item.id) {
            const qty = Math.floor(Number(bet.item.qty) || 0);
            if (qty > 0) item = { id: String(bet.item.id), qty: qty };
        }
    }
    if (coins <= 0 && !item) return { error: 'La apuesta debe incluir monedas y/o un personaje' };
    if (coins > 0 && data.coins < coins) return { error: 'No tienes suficientes monedas para apostar' };
    if (item && (!data.owned[item.id] || data.owned[item.id] < item.qty)) return { error: 'No posees ese personaje para apostar' };
    return { coins: coins, item: item };
}

function escrowFromUser(user, bet) {
    const data = ownData(user);
    const escrow = { coins: bet.coins, items: {} };
    if (bet.coins > 0) data.coins -= bet.coins;
    if (bet.item) {
        data.owned[bet.item.id] = (data.owned[bet.item.id] || 0) - bet.item.qty;
        escrow.items[bet.item.id] = (escrow.items[bet.item.id] || 0) + bet.item.qty;
    }
    return escrow;
}

function refundEscrow(user, escrow) {
    if (!escrow) return;
    const data = ownData(user);
    const sz = escrowSize(escrow);
    if (sz.coins > 0) data.coins += sz.coins;
    for (const id in sz.items) data.owned[id] = (data.owned[id] || 0) + sz.items[id];
}

function publicMatchView(m, meKey) {
    const isChallenger = String(m.challenger.key) === meKey;
    const me = isChallenger ? m.challenger : m.opponent;
    const op = isChallenger ? m.opponent : m.challenger;
    const view = (player, own, oppName) => ({
        key: player.key,
        username: player.username,
        hp: player.hp,
        energy: player.energy,
        handSize: (player.hand || []).length,
        hand: own ? (player.hand || []).slice() : [],
        field: (player.field || []).map(f => own ? f : { uid: f.uid, id: f.id, atk: f.atk, hp: f.hp, canAttack: false }),
        deckLen: (player.deck || []).length,
        confirm: !!player.confirm,
        bet: player.bet || null,
        escrow: player.escrow ? escrowSize(player.escrow) : { coins: 0, items: {} },
        deckSelected: Array.isArray(player.deckSelected) ? player.deckSelected.slice() : null,
        lastSeen: player.lastSeen || 0,
    });
    return {
        id: m.id,
        status: m.status,
        version: m.version,
        turn: m.turn,
        phase: m.phase,
        winner: m.winner ? m.winner.username : null,
        reason: m.reason || null,
        result: m.result || null,
        isChallenger: isChallenger,
        me: view(me, true, op.username),
        opponent: view(op, false, me.username),
        log: m.log,
        createdAt: m.createdAt,
    };
}

function buildAutoDeck(user, users) {
    const data = ownData(user);
    const chanceMap = getItemChanceMap();
    const ownedIds = Object.keys(data.owned).filter(id => (data.owned[id] || 0) > 0);
    const pool = [];
    for (const id of ownedIds) {
        const w = Math.max(1, Math.round(500000 / Math.max(1, chanceMap[id] || 500000)));
        for (let i = 0; i < w && i < 8; i++) pool.push(id);
    }
    const deck = [];
    const bag = pool.slice();
    while (deck.length < PVP_MAX_DECK && bag.length > 0) {
        const idx = Math.floor(Math.random() * bag.length);
        deck.push(bag.splice(idx, 1)[0]);
    }
    return deck;
}

function startPlaying(m) {
    const users = loadUsers();
    const a = users[m.challenger.key];
    const b = users[m.opponent.key];
    m.status = 'playing';
    m.winner = null;
    m.reason = null;
    for (const pl of [m.challenger, m.opponent]) {
        const u = pl.key === m.challenger.key ? a : b;
        const chosen = Array.isArray(pl.deckSelected) && pl.deckSelected.length > 0 ? pl.deckSelected : null;
        let deck = chosen;
        if (!deck) deck = buildAutoDeck(u, users);
        deck = deck.slice(0, PVP_MAX_DECK);
        pl.deck = deck.slice();
        pl.deckLen = deck.length;
        pl.hand = [];
        pl.field = [];
        pl.energy = PVP_START_ENERGY;
        pl.hp = PVP_START_HP;
        pl.dealtThisTurn = 0;
    }
    m.turn = 0;
    m.phase = 'play';
    m.version++;
    drawAtTurnStart(m, m.challenger);
    const c = m.challenger, o = m.opponent;
    addLogHelper(m, `${c.username} empieza la partida`, 'system');
    addLogHelper(m, `${c.username}: ${c.hand.length} cartas en mano`, 'draw');
    addLogHelper(m, `${o.username}: ${o.hand.length} cartas en mano`, 'draw');
    addLogHelper(m, `Turno de ${c.username}`, 'turn');
}

function drawAtTurnStart(m, pl) {
    for (let i = 0; i < PVP_START_HAND; i++) {
        if (pl.hand.length >= PVP_MAX_HAND) break;
        if (pl.deck.length === 0) { addLogHelper(m, `${pl.username} no tiene cartas que robar`, 'draw'); return; }
        pl.hand.push(pl.deck.shift());
    }
}

function endTurn(m, pl) {
    pl.energy = Math.min(PVP_MAX_ENERGY, pl.energy + PVP_TURN_ENERGY);
    for (const f of pl.field) f.canAttack = true;
    m.turn = m.turn === 0 ? 1 : 0;
    m.phase = 'play';
    const next = m.turn === 0 ? m.challenger : m.opponent;
    if (next.deck.length === 0 && next.hand.length >= PVP_MAX_HAND) {
        m.reason = 'deckout';
        m.winner = m.turn === 0 ? m.opponent : m.challenger;
        addLogHelper(m, `${next.username} se queda sin cartas y pierde`, 'system');
        finalizeMatch(m);
        return;
    }
    drawAtTurnStart(m, next);
    addLogHelper(m, `Turno de ${next.username} (+${PVP_TURN_ENERGY} energía)`, 'turn');
    m.version++;
}

function finalizeMatch(m) {
    if (m.status === 'finished') return;
    const users = loadUsers();
    const a = users[m.challenger.key];
    const b = users[m.opponent.key];
    if (m.winner) {
        const isC = String(m.winner.key) === String(m.challenger.key);
        const w = isC ? m.challenger : m.opponent;
        const l = isC ? m.opponent : m.challenger;
        const wUser = isC ? a : b;
        const gains = { coins: 0, items: {} };
        const ws = escrowSize(w.escrow);
        const ls = escrowSize(l.escrow);
        gains.coins = (ws.coins || 0) + (ls.coins || 0);
        for (const id in ws.items) gains.items[id] = (gains.items[id] || 0) + ws.items[id];
        for (const id in ls.items) gains.items[id] = (gains.items[id] || 0) + ls.items[id];
        addWinningsToUser(wUser, gains);
        m.result = {
            winner: w.username,
            loser: l.username,
            gained: gains,
            lost: escrowSize(l.escrow),
        };
        addLogHelper(m, `${w.username} gana la partida${m.reason ? ' (' + m.reason + ')' : ''}`, 'win');
        const entry = {
            id: m.id,
            at: Date.now(),
            winner: w.username,
            loser: l.username,
            reason: m.reason || 'normal',
            bets: { winner: escrowSize(w.escrow), loser: escrowSize(l.escrow), gained: gains },
        };
        pvpResultsLog.unshift(entry);
        if (pvpResultsLog.length > 200) pvpResultsLog.length = 200;
        savePvpLog();
        saveUsers(users);
    } else {
        // empate imposible salvo desconexión mutua
        for (const pl of [m.challenger, m.opponent]) {
            const u = pl.key === m.challenger.key ? a : b;
            if (u) refundEscrow(u, pl.escrow);
        }
        m.result = { winner: null, loser: null, gained: { coins: 0, items: {} }, lost: { coins: 0, items: {} } };
        saveUsers(users);
    }
    m.status = 'finished';
    m.version++;
}

function handlePvpPlayers(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const users = loadUsers();
    const meKey = user.username.toLowerCase();
    const list = [];
    for (const key of Object.keys(users)) {
        if (key === meKey) continue;
        const u = users[key];
        if (!u.username) continue;
        const online = isOnline(u);
        const mActive = pvpMatchForKey(key);
        let status = 'offline';
        if (online) {
            if (mActive && (mActive.status === 'playing' || mActive.status === 'preparing')) status = 'enpartida';
            else status = 'disponible';
        }
        list.push({ username: u.username, status: status, online: online, inMatch: !!mActive });
    }
    sendJson(res, 200, { ok: true, players: list });
}

function handlePvpChallenge(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        if (pvpMatchForKey(meKey)) return sendJson(res, 400, { error: 'Ya estás en una partida o desafío' });
        const targetKey = String(parsed.target || '').toLowerCase();
        const target = users[targetKey];
        if (!target || !target.username) return sendJson(res, 400, { error: 'Jugador no encontrado' });
        if (targetKey === meKey) return sendJson(res, 400, { error: 'No puedes desafiarte a ti mismo' });
        if (!isOnline(target)) return sendJson(res, 400, { error: 'Ese jugador no está online' });
        if (pvpMatchForKey(targetKey)) return sendJson(res, 400, { error: 'Ese jugador ya está en una partida' });
        const bet = validateBet(user, parsed.bet, users);
        if (bet.error) return sendJson(res, 400, { error: bet.error });
        const escrow = escrowFromUser(user, bet);
        const m = {
            id: crypto.randomBytes(5).toString('hex'),
            status: 'open',
            version: 0,
            turn: 0,
            phase: 'play',
            log: [],
            createdAt: Date.now(),
            winner: null,
            reason: null,
            result: null,
            challenger: {
                key: meKey, username: user.username, bet: bet, escrow: escrow,
                confirm: false, deckSelected: null, lastSeen: Date.now(),
            },
            opponent: {
                key: targetKey, username: target.username, bet: null, escrow: { coins: 0, items: {} },
                confirm: false, deckSelected: null, lastSeen: Date.now(),
            },
        };
        m.log = [];
        addLogHelper(m, `${m.challenger.username} te ha desafiado a una partida`, 'challenge', { actor: m.challenger.username });
        pvpMatches.set(m.id, m);
        saveUsers(users);
        sendJson(res, 200, { ok: true, matchId: m.id });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handlePvpPending(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const meKey = user.username.toLowerCase();
    const out = [];
    for (const m of pvpMatches.values()) {
        if (m.status === 'open' && String(m.opponent.key) === meKey) {
            out.push({ matchId: m.id, challenger: m.challenger.username, bet: m.challenger.bet, escrow: escrowSize(m.challenger.escrow), createdAt: m.createdAt });
        }
    }
    sendJson(res, 200, { ok: true, pending: out });
}

function findPvpMatchById(id) {
    return pvpMatches.get(String(id || '')) || null;
}

function handlePvpRespond(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m || m.status !== 'open') return sendJson(res, 400, { error: 'Desafío no encontrado o ya respondido' });
        if (String(m.opponent.key) !== meKey) return sendJson(res, 400, { error: 'No formas parte de este desafío' });
        if (parsed.accept !== 'true' && parsed.accept !== true) {
            refundEscrow(users[m.challenger.key], m.challenger.escrow);
            m.challenger.escrow = { coins: 0, items: {} };
            m.status = 'cancelled';
            addLogHelper(m, `${user.username} rechazó el desafío`, 'system');
            m.version++;
            pvpMatches.delete(m.id);
            saveUsers(users);
            return sendJson(res, 200, { ok: true, accepted: false });
        }
        let otherMatch = null;
        for (const mm of pvpMatches.values()) {
            if (mm.id === m.id) continue;
            if (String(mm.challenger.key) === meKey || String(mm.opponent.key) === meKey) { otherMatch = mm; break; }
        }
        if (otherMatch) {
            refundEscrow(users[m.challenger.key], m.challenger.escrow);
            m.challenger.escrow = { coins: 0, items: {} };
            pvpMatches.delete(m.id);
            saveUsers(users);
            return sendJson(res, 400, { error: 'Ya estás en una partida' });
        }
        const bet = validateBet(user, parsed.bet, users);
        if (bet.error) {
            refundEscrow(users[m.challenger.key], m.challenger.escrow);
            m.challenger.escrow = { coins: 0, items: {} };
            pvpMatches.delete(m.id);
            saveUsers(users);
            return sendJson(res, 400, { error: bet.error });
        }
        m.opponent.bet = bet;
        m.opponent.escrow = escrowFromUser(user, bet);
        m.status = 'preparing';
        m.opponent.lastSeen = Date.now();
        m.challenger.lastSeen = Date.now();
        addLogHelper(m, `${m.opponent.username} aceptó el desafío`, 'system');
        addLogHelper(m, `${m.opponent.username} apuesta: ${betStr(bet)}`, 'bet');
        m.version++;
        saveUsers(users);
        sendJson(res, 200, { ok: true, accepted: true, matchId: m.id });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function betStr(bet) {
    const parts = [];
    if (bet && bet.coins > 0) parts.push(bet.coins.toLocaleString() + ' 🪙');
    if (bet && bet.item) parts.push('👤 ' + (bet.item.qty > 1 ? bet.item.qty + 'x ' : '') + bet.item.id);
    return parts.join(' + ') || 'nada';
}

function handlePvpBet(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m || m.status !== 'preparing') return sendJson(res, 400, { error: 'Solo se puede cambiar la apuesta antes de confirmar' });
        const pl = String(m.challenger.key) === meKey ? m.challenger : (String(m.opponent.key) === meKey ? m.opponent : null);
        if (!pl) return sendJson(res, 400, { error: 'No formas parte de esta partida' });
        const bet = validateBet(user, parsed.bet, users);
        if (bet.error) return sendJson(res, 400, { error: bet.error });
        refundEscrow(users[meKey], pl.escrow);
        pl.escrow = escrowFromUser(user, bet);
        pl.bet = bet;
        pl.confirm = false;
        pl.lastSeen = Date.now();
        addLogHelper(m, `${pl.username} actualizó su apuesta: ${betStr(bet)}`, 'bet');
        m.version++;
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handlePvpDeck(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m || (m.status !== 'preparing' && m.status !== 'open')) return sendJson(res, 400, { error: 'No puedes modificar el mazo ahora' });
        const pl = String(m.challenger.key) === meKey ? m.challenger : (String(m.opponent.key) === meKey ? m.opponent : null);
        if (!pl) return sendJson(res, 400, { error: 'No formas parte de esta partida' });
        const data = ownData(user);
        const ids = Array.isArray(parsed.deckIds) ? parsed.deckIds.map(String) : [];
        if (ids.length > PVP_MAX_DECK) return sendJson(res, 400, { error: 'El mazo máximo es de ' + PVP_MAX_DECK + ' cartas' });
        const counts = {};
        for (const id of ids) counts[id] = (counts[id] || 0) + 1;
        for (const id in counts) if ((data.owned[id] || 0) < counts[id]) return sendJson(res, 400, { error: 'No posees suficientes cartas para ese mazo' });
        pl.deckSelected = ids;
        pl.lastSeen = Date.now();
        m.version++;
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handlePvpConfirm(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m || m.status !== 'preparing') return sendJson(res, 400, { error: 'Partida no encontrada' });
        const pl = String(m.challenger.key) === meKey ? m.challenger : (String(m.opponent.key) === meKey ? m.opponent : null);
        if (!pl) return sendJson(res, 400, { error: 'No formas parte de esta partida' });
        pl.confirm = true;
        pl.lastSeen = Date.now();
        addLogHelper(m, `${pl.username} confirmó la apuesta`, 'system');
        m.version++;
        if (m.challenger.confirm && m.opponent.confirm) {
            addLogHelper(m, '¡Apuestas confirmadas! Empieza la partida', 'system');
            startPlaying(m);
        }
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handlePvpCancel(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const users = loadUsers();
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m || (m.status !== 'open' && m.status !== 'preparing')) return sendJson(res, 400, { error: 'No se puede cancelar ahora' });
        if (String(m.challenger.key) !== meKey && String(m.opponent.key) !== meKey) return sendJson(res, 400, { error: 'No formas parte de esta partida' });
        refundEscrow(users[m.challenger.key], m.challenger.escrow);
        refundEscrow(users[m.opponent.key], m.opponent.escrow);
        m.challenger.escrow = { coins: 0, items: {} };
        m.opponent.escrow = { coins: 0, items: {} };
        m.status = 'cancelled';
        addLogHelper(m, `${user.username} canceló la partida`, 'system');
        m.version++;
        pvpMatches.delete(m.id);
        saveUsers(users);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handlePvpState(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const m = findPvpMatchById(req.headers['x-match']);
    if (!m) return sendJson(res, 404, { error: 'Partida no encontrada' });
    const meKey = user.username.toLowerCase();
    if (String(m.challenger.key) !== meKey && String(m.opponent.key) !== meKey) return sendJson(res, 403, { error: 'No formas parte de esta partida' });
    const pl = String(m.challenger.key) === meKey ? m.challenger : m.opponent;
    pl.lastSeen = Date.now();
    m.updatedAt = Date.now();
    sendJson(res, 200, { ok: true, match: publicMatchView(m, meKey) });
}

function handlePvpCurrent(req, res) {
    const user = findUserByToken(req.headers['x-token']);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const meKey = user.username.toLowerCase();
    const m = pvpMatchForKey(meKey);
    if (!m || m.status === 'finished' || m.status === 'cancelled') return sendJson(res, 200, { ok: true, match: null });
    const pl = String(m.challenger.key) === meKey ? m.challenger : m.opponent;
    pl.lastSeen = Date.now();
    m.updatedAt = Date.now();
    sendJson(res, 200, { ok: true, match: publicMatchView(m, meKey) });
}

function handlePvpAction(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const user = findUserByToken(parsed.token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        const meKey = user.username.toLowerCase();
        const m = findPvpMatchById(parsed.matchId);
        if (!m) return sendJson(res, 404, { error: 'Partida no encontrada' });
        if (String(m.challenger.key) !== meKey && String(m.opponent.key) !== meKey) return sendJson(res, 403, { error: 'No formas parte de esta partida' });
        const pl = String(m.challenger.key) === meKey ? m.challenger : m.opponent;
        const op = pl.key === m.challenger.key ? m.opponent : m.challenger;
        const isMyTurn = (m.turn === 0 && pl.key === m.challenger.key) || (m.turn === 1 && pl.key === m.opponent.key);
        if (m.status === 'finished') return sendJson(res, 400, { error: 'La partida ya terminó' });
        if (m.status !== 'playing') return sendJson(res, 400, { error: 'La partida no ha empezado' });
        const act = parsed.action || {};

        if (act.type === 'concede') {
            m.winner = op;
            m.reason = 'abandono';
            addLogHelper(m, `${pl.username} abandonó la partida`, 'system');
            finalizeMatch(m);
            saveUsers(loadUsers());
            return sendJson(res, 200, { ok: true });
        }
        if (act.type === 'end') {
            if (!isMyTurn) return sendJson(res, 400, { error: 'No es tu turno' });
            pl.lastSeen = Date.now();
            addLogHelper(m, `${pl.username} terminó su turno`, 'turn');
            endTurn(m, pl);
            saveUsers(loadUsers());
            return sendJson(res, 200, { ok: true });
        }
        if (act.type === 'play') {
            if (!isMyTurn) return sendJson(res, 400, { error: 'No es tu turno' });
            const handIdx = Math.floor(Number(act.card) || 0);
            if (handIdx < 0 || handIdx >= (pl.hand || []).length) return sendJson(res, 400, { error: 'Carta no válida' });
            const slot = Math.floor(Number(act.slot) || 0);
            if (slot < 0 || slot >= PVP_MAX_FIELD) return sendJson(res, 400, { error: 'Slot de campo no válido' });
            if ((pl.field || []).length >= PVP_MAX_FIELD) return sendJson(res, 400, { error: 'Campo lleno' });
            const id = pl.hand[handIdx];
            const stats = cardForId(id);
            if (pl.energy < stats.cost) return sendJson(res, 400, { error: 'Energía insuficiente' });
            pl.energy -= stats.cost;
            pl.hand.splice(handIdx, 1);
            if (pl.field.length >= PVP_MAX_FIELD) return sendJson(res, 400, { error: 'Campo lleno' });
            pl.field.push({ uid: m.version + '-' + pl.field.length, id: id, atk: stats.atk, hp: stats.hp, cost: stats.cost, canAttack: true });
            addLogHelper(m, `${pl.username} juega '${id}'`, 'play');
            m.version++;
            saveUsers(loadUsers());
            return sendJson(res, 200, { ok: true });
        }
        if (act.type === 'attack') {
            if (!isMyTurn) return sendJson(res, 400, { error: 'No es tu turno' });
            const atkIdx = Math.floor(Number(act.attacker) || 0);
            if (atkIdx < 0 || atkIdx >= (pl.field || []).length) return sendJson(res, 400, { error: 'Atacante no válido' });
            const attacker = pl.field[atkIdx];
            if (!attacker.canAttack) return sendJson(res, 400, { error: 'Esa carta ya atacó este turno' });
            if (act.target === 'face') {
                attacker.canAttack = false;
                op.hp -= attacker.atk;
                addLogHelper(m, `${attacker.id} ataca la cara de ${op.username} (-${attacker.atk})`, 'attack');
                m.version++;
                if (op.hp <= 0) {
                    m.reason = 'hp';
                    m.winner = pl;
                    addLogHelper(m, `${op.username} pierde todos sus PV`, 'system');
                    finalizeMatch(m);
                    saveUsers(loadUsers());
                    return sendJson(res, 200, { ok: true });
                }
                saveUsers(loadUsers());
                return sendJson(res, 200, { ok: true });
            }
            const tIdx = Math.floor(Number(act.target) || 0);
            if (tIdx < 0 || tIdx >= (op.field || []).length) return sendJson(res, 400, { error: 'Objetivo no válido' });
            const target = op.field[tIdx];
            attacker.canAttack = false;
            target.hp -= attacker.atk;
            addLogHelper(m, `${attacker.id} ataca a ${target.id} (-${attacker.atk})`, 'attack');
            m.version++;
            if (target.hp <= 0) {
                op.field.splice(tIdx, 1);
                addLogHelper(m, `${target.id} es derrotado`, 'kill');
            }
            saveUsers(loadUsers());
            return sendJson(res, 200, { ok: true });
        }
        return sendJson(res, 400, { error: 'Acción no válida' });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

setInterval(() => {
    const users = loadUsers();
    const now = Date.now();
    for (const [id, m] of pvpMatches) {
        if (m.status === 'finished' || m.status === 'cancelled') {
            pvpMatches.delete(id);
            continue;
        }
        if (m.status === 'open') {
            if (now - (m.challenger.lastSeen || 0) > PVP_CANCEL_MS || now - (m.opponent.lastSeen || 0) > PVP_CANCEL_MS) {
                refundEscrow(users[m.challenger.key], m.challenger.escrow);
                refundEscrow(users[m.opponent.key], m.opponent.escrow);
                m.challenger.escrow = { coins: 0, items: {} };
                m.opponent.escrow = { coins: 0, items: {} };
                addLogHelper(m, 'Desafío cancelado por inactividad', 'system');
                m.status = 'cancelled';
                m.version++;
                saveUsers(users);
                pvpMatches.delete(id);
            }
            continue;
        }
        if (m.status === 'preparing') {
            if (now - (m.challenger.lastSeen || 0) > PVP_CANCEL_MS || now - (m.opponent.lastSeen || 0) > PVP_CANCEL_MS) {
                refundEscrow(users[m.challenger.key], m.challenger.escrow);
                refundEscrow(users[m.opponent.key], m.opponent.escrow);
                m.challenger.escrow = { coins: 0, items: {} };
                m.opponent.escrow = { coins: 0, items: {} };
                addLogHelper(m, 'Preparación cancelada por inactividad', 'system');
                m.status = 'cancelled';
                m.version++;
                saveUsers(users);
                pvpMatches.delete(id);
            }
            continue;
        }
        if (m.status === 'playing') {
            const aGone = now - (m.challenger.lastSeen || 0) > PVP_TIMEOUT_MS;
            const bGone = now - (m.opponent.lastSeen || 0) > PVP_TIMEOUT_MS;
            if (aGone && !bGone) {
                m.winner = m.opponent;
                m.reason = 'desconexión';
                addLogHelper(m, `${m.challenger.username} se desconectó. Gana ${m.opponent.username}`, 'system');
                finalizeMatch(m);
                saveUsers(users);
            } else if (bGone && !aGone) {
                m.winner = m.challenger;
                m.reason = 'desconexión';
                addLogHelper(m, `${m.opponent.username} se desconectó. Gana ${m.challenger.username}`, 'system');
                finalizeMatch(m);
                saveUsers(users);
            } else if (aGone && bGone) {
                refundEscrow(users[m.challenger.key], m.challenger.escrow);
                refundEscrow(users[m.opponent.key], m.opponent.escrow);
                m.challenger.escrow = { coins: 0, items: {} };
                m.opponent.escrow = { coins: 0, items: {} };
                addLogHelper(m, 'Ambos jugadores se desconectaron: apuestas devueltas', 'system');
                finalizeMatch(m);
                saveUsers(users);
            }
        }
    }
}, 10000);

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
    if (pvpHasBet(user.username.toLowerCase())) return sendJson(res, 403, { error: 'No puedes guardar datos mientras tienes una apuesta activa en PvP' });
    if (getTrade(user.username.toLowerCase(), ['active'])) return sendJson(res, 403, { error: 'No puedes guardar datos mientras tienes un trade activo' });
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
        if (key === ADMIN_ACCOUNT) continue;
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
let tradeChatMessages = {};
const TRADE_CHAT_MAX = 50;

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
    delete tradeChatMessages[t.id];
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
    delete tradeChatMessages[t.id];
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

function getTradeChat(tradeId) {
    const list = tradeChatMessages[tradeId] || [];
    if (list.length > TRADE_CHAT_MAX) {
        tradeChatMessages[tradeId] = list.slice(-TRADE_CHAT_MAX);
        return tradeChatMessages[tradeId];
    }
    return list;
}

function pushTradeChat(t, message) {
    pushToUser(t.from, { type: 'tradeChat', tradeId: t.id, message });
    pushToUser(t.to, { type: 'tradeChat', tradeId: t.id, message });
}

function handleTradeChatSend(req, res) {
    readBody(req).then(body => {
        let parsed;
        try { parsed = JSON.parse(body || '{}'); } catch (e) { parsed = {}; }
        const { token, tradeId, text } = parsed;
        const user = findUserByToken(token);
        if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
        if (!isOnline(user)) return sendJson(res, 403, { error: 'Solo los jugadores conectados al juego pueden escribir' });
        const t = activeTrades[tradeId];
        if (!t || t.status !== 'active') return sendJson(res, 400, { error: 'El trade ya no está activo' });
        const meKey = user.username.toLowerCase();
        if (!(String(t.from).toLowerCase() === meKey || String(t.to).toLowerCase() === meKey)) return sendJson(res, 403, { error: 'No formas parte de este trade' });
        const msgText = String(text || '').trim();
        if (!msgText) return sendJson(res, 400, { error: 'Mensaje vacío' });
        if (msgText.length > 300) return sendJson(res, 400, { error: 'El mensaje es demasiado largo' });
        const users = loadUsers();
        const me = users[meKey];
        if (!me) return sendJson(res, 401, { error: 'Sesión inválida' });
        const now = Date.now();
        if (chatLastSent[meKey] && now - chatLastSent[meKey] < 1500) {
            return sendJson(res, 429, { error: 'Espera un momento antes de seguir escribiendo' });
        }
        chatLastSent[meKey] = now;
        if (!tradeChatMessages[tradeId]) tradeChatMessages[tradeId] = [];
        tradeChatMessages[tradeId].push({ user: me.username, text: msgText, at: now });
        if (tradeChatMessages[tradeId].length > TRADE_CHAT_MAX) tradeChatMessages[tradeId] = tradeChatMessages[tradeId].slice(-TRADE_CHAT_MAX);
        const list = tradeChatMessages[tradeId];
        pushTradeChat(t, list[list.length - 1]);
        sendJson(res, 200, { ok: true });
    }).catch(() => sendJson(res, 500, { error: 'Error interno' }));
}

function handleTradeChatHistory(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || '';
    const tradeId = url.searchParams.get('tradeId') || '';
    const user = findUserByToken(token);
    if (!user) return sendJson(res, 401, { error: 'Sesión inválida' });
    const t = activeTrades[tradeId];
    if (!t) return sendJson(res, 400, { error: 'Trade no encontrado' });
    const meKey = user.username.toLowerCase();
    if (!(String(t.from).toLowerCase() === meKey || String(t.to).toLowerCase() === meKey)) return sendJson(res, 403, { error: 'No formas parte de este trade' });
    sendJson(res, 200, { ok: true, messages: getTradeChat(tradeId) });
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
        delete tradeChatMessages[tradeId];
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
            'Access-Control-Allow-Headers': 'Content-Type, x-token, x-match',
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
            if (urlPath === '/api/casino/spin' && req.method === 'POST') {
                return handleCasinoSpin(req, res);
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
    if (urlPath === '/api/trade/chat/send' && req.method === 'POST') {
        return handleTradeChatSend(req, res);
    }
    if (urlPath === '/api/trade/chat/history' && req.method === 'GET') {
        return handleTradeChatHistory(req, res);
    }

    if (urlPath === '/api/pvp/players' && req.method === 'GET') {
        return handlePvpPlayers(req, res);
    }
    if (urlPath === '/api/pvp/challenge' && req.method === 'POST') {
        return handlePvpChallenge(req, res);
    }
    if (urlPath === '/api/pvp/pending' && req.method === 'GET') {
        return handlePvpPending(req, res);
    }
    if (urlPath === '/api/pvp/respond' && req.method === 'POST') {
        return handlePvpRespond(req, res);
    }
    if (urlPath === '/api/pvp/bet' && req.method === 'POST') {
        return handlePvpBet(req, res);
    }
    if (urlPath === '/api/pvp/deck' && req.method === 'POST') {
        return handlePvpDeck(req, res);
    }
    if (urlPath === '/api/pvp/confirm' && req.method === 'POST') {
        return handlePvpConfirm(req, res);
    }
    if (urlPath === '/api/pvp/cancel' && req.method === 'POST') {
        return handlePvpCancel(req, res);
    }
    if (urlPath === '/api/pvp/state' && req.method === 'GET') {
        return handlePvpState(req, res);
    }
    if (urlPath === '/api/pvp/current' && req.method === 'GET') {
        return handlePvpCurrent(req, res);
    }
    if (urlPath === '/api/pvp/action' && req.method === 'POST') {
        return handlePvpAction(req, res);
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