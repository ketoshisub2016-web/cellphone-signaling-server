// 変更日時：2026年10月31日 12時09分
// ============================================================================
// GitHub (https://github.com/ketoshisub2016-web/cellphone-signaling-server/edit/main/server.js)
// 単一ファイル貼り付け用バンドル (server/server_single_for_github.js)
// ※ server/server.js または server/modules/*.js 変更時に自動上書き生成されます
// ============================================================================
const __internalModules = {};
function __requireModule(name) { return __internalModules[name]; }

// ==================== [Module: ./modules/stateStore.js] ====================
__internalModules['./modules/stateStore'] = (function(module, exports) {
// 変更日時：2026年10月31日 12時08分
// [サーバーモジュール] セッション・オフラインキュー・FCMトークン・レート制限・暗号化永続化ストア

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SERVER_DIR = path.join(__dirname, '..');
const DATA_DIR = path.join(SERVER_DIR, 'data');

// 許可されたGoogleアカウントのSHA-256ハッシュリスト (小文字Hex)
const ALLOWED_EMAIL_HASHES = new Set([
    '6838c7018bdd3e8d610196e5eeead1841bbba1f577d1a241aca19a0517edd5ac', // satochan...
    '64ade2628e31414cfd703856b95d20762039f9eb7a252bd4f82ad30654f827c0', // ketoshi...
    'cc62be47a00bd185613ae382f18ff5e162a525d01a36b72032e1efa086000597'  // tutuzi...
]);

// 相互承認ルーティングマップ (ログイン試行者 -> ワンタイム承認コード送信先)
const APPROVAL_ROUTING = {
    'satochan.07620@gmail.com': 'ketoshisub.2016@gmail.com',
    'ketoshisub.2016@gmail.com': 'satochan.07620@gmail.com',
    'tutuzisann@gmail.com': 'satochan.07620@gmail.com'
};

// 3日間 (72時間) スライディング有効期限定数
const SESSION_DURATION_MS = 3 * 24 * 60 * 60 * 1000;

// 永続化ファイルパス
const SECRET_KEY_FILE = path.join(DATA_DIR, 'hmac_secret.key');
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, 'revoked_tokens.json');
const SESSIONS_FILE = path.join(SERVER_DIR, 'sessions.json');
const QUEUE_FILE_PATH = path.join(DATA_DIR, 'offline_queue.json');
const FCM_TOKENS_FILE = path.join(SERVER_DIR, 'fcm_tokens.json');
const OFFLINE_READS_FILE = path.join(SERVER_DIR, 'offline_reads.json');
const ATTACHMENT_ACLS_FILE = path.join(DATA_DIR, 'attachment_acls.json');

// サーバーHMAC暗号シークレット取得（環境変数最優先、次に永続化ファイル、未作成時は強力な32バイト乱数自動生成: VULN-02是正）
function loadOrCreateServerHmacSecret()
{
    const envSecret = (process.env.SESSION_HMAC_SECRET || '').trim();
    if (envSecret.length >= 32)
    {
        return envSecret;
    }

    try
    {
        if (!fs.existsSync(DATA_DIR))
        {
            fs.mkdirSync(DATA_DIR, { recursive: true });
        }
        if (fs.existsSync(SECRET_KEY_FILE))
        {
            const savedKey = fs.readFileSync(SECRET_KEY_FILE, 'utf8').trim();
            if (savedKey.length >= 32)
            {
                return savedKey;
            }
        }

        // 固定文字列導出を廃止し、強力な暗号乱数キーを生成して保護保存
        const newSecret = crypto.randomBytes(32).toString('hex');
        fs.writeFileSync(SECRET_KEY_FILE, newSecret, { mode: 0o600 });
        console.log('[Security] 新規サーバーHMACシークレットキーを生成・保存しました');
        return newSecret;
    }
    catch (err)
    {
        console.warn('[Security Warning] シークレットファイル保存失敗。一時メモリ乱数を使用:', err.message);
        return crypto.randomBytes(32).toString('hex');
    }
}

const SERVER_HMAC_SECRET = loadOrCreateServerHmacSecret();
const STATE_ENC_KEY = crypto.createHash('sha256').update(`STATE_AES_GCM:${SERVER_HMAC_SECRET}`).digest();

// 各種インメモリストア
const fcmTokenStore = new Map();
const ipConnectionTracker = new Map();
const otpStore = new Map();
const activeSessions = new Map();
const revokedTokens = new Map();
const seenInviteNonces = new Set();
const emailOtpCooldownTracker = new Map();
const offlineMessageQueue = new Map();
const offlineReadQueue = new Map();
const attachmentAclStore = new Map();
const recentChatPacketIds = new Map();
const rooms = new Map();
const users = new Map();
const wsIpConnectionCount = new Map();

// Mapの最大エントリ数上限保護 (メモリ枯渇DoS防止: No.16対策)
function enforceMapSizeCap(map, maxEntries = 5000)
{
    while (map.size > maxEntries)
    {
        const oldestKey = map.keys().next().value;
        if (oldestKey === undefined) { break; }
        map.delete(oldestKey);
    }
}

// 永続化ファイル用AES-256-GCM暗号化・復号ヘルパー (No.16対策)
function writeEncryptedJsonFile(filePath, obj)
{
    try
    {
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir))
        {
            fs.mkdirSync(dir, { recursive: true });
        }
        const plain = JSON.stringify(obj);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', STATE_ENC_KEY, iv);
        const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        const payload = `ENC_STATE_V1:${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
        fs.writeFileSync(filePath, payload, { encoding: 'utf8', mode: 0o600 });
    }
    catch (e)
    {
        console.error(`[Encrypted Store] 保存エラー (${path.basename(filePath)}):`, e.message);
    }
}

function readEncryptedJsonFile(filePath)
{
    if (!fs.existsSync(filePath)) { return null; }
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) { return null; }
    if (raw.startsWith('ENC_STATE_V1:'))
    {
        const parts = raw.split(':');
        if (parts.length !== 4) { return null; }
        const iv = Buffer.from(parts[1], 'hex');
        const tag = Buffer.from(parts[2], 'hex');
        const enc = Buffer.from(parts[3], 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', STATE_ENC_KEY, iv);
        decipher.setAuthTag(tag);
        const decStr = Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
        return JSON.parse(decStr);
    }
    return JSON.parse(raw);
}

// メールアドレスの伏字マスク
function maskEmail(addr)
{
    if (!addr || !addr.includes('@')) { return addr || ''; }
    const parts = addr.split('@');
    const name = parts[0];
    const visible = name.length > 3 ? name.slice(0, 3) : name.slice(0, 1);
    return `${visible}***@${parts[1]}`;
}

// 文字列のSHA-256ハッシュ算出
function sha256(text)
{
    return crypto.createHash('sha256').update(String(text || '').toLowerCase().trim()).digest('hex');
}

function saveRevokedTokens()
{
    const obj = {};
    const now = Date.now();
    for (const [k, exp] of revokedTokens.entries())
    {
        if (exp > now) { obj[k] = exp; }
    }
    writeEncryptedJsonFile(REVOKED_TOKENS_FILE, obj);
}

function loadRevokedTokens()
{
    try
    {
        const obj = readEncryptedJsonFile(REVOKED_TOKENS_FILE);
        if (!obj) { return; }
        const now = Date.now();
        for (const [k, exp] of Object.entries(obj))
        {
            if (Number(exp) > now) { revokedTokens.set(k, Number(exp)); }
        }
    }
    catch (e)
    {
        console.error('[Revoked Token Store] 復元エラー:', e.message);
    }
}

// トークン失効登録 (No.03 ゾンビセッション完全遮断)
function revokeSessionToken(token)
{
    if (!token || typeof token !== 'string') { return; }
    const exp = Date.now() + SESSION_DURATION_MS;
    const tokenHash = sha256(token);
    revokedTokens.set(tokenHash, exp);
    if (token.startsWith('st1.'))
    {
        try
        {
            const parts = token.split('.');
            if (parts.length === 3)
            {
                const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
                if (payload && payload.jti)
                {
                    revokedTokens.set(`jti:${payload.jti}`, payload.exp || exp);
                }
            }
        }
        catch (e) {}
    }
    activeSessions.delete(token);
    enforceMapSizeCap(revokedTokens, 10000);
    saveRevokedTokens();
    saveSessions();
}

function isTokenRevoked(token, jti = '')
{
    if (!token || typeof token !== 'string') { return true; }
    const now = Date.now();
    const tokenHash = sha256(token);
    const exp = revokedTokens.get(tokenHash);
    if (exp && exp > now) { return true; }
    if (jti)
    {
        const jtiExp = revokedTokens.get(`jti:${jti}`);
        if (jtiExp && jtiExp > now) { return true; }
    }
    return false;
}

function saveSessions()
{
    const obj = {};
    for (const [k, v] of activeSessions.entries())
    {
        obj[k] = v;
    }
    writeEncryptedJsonFile(SESSIONS_FILE, obj);
}

function loadSessions()
{
    try
    {
        const obj = readEncryptedJsonFile(SESSIONS_FILE);
        if (!obj) { return; }
        const now = Date.now();
        for (const [k, v] of Object.entries(obj))
        {
            if (v && v.expiresAt > now && !isTokenRevoked(k, v.jti))
            {
                activeSessions.set(k, v);
            }
        }
        console.log(`[Session Store] ${activeSessions.size} 件のアクティブセッションを復元完了`);
    }
    catch (e)
    {
        console.error('[Session Store] 復元エラー:', e.message);
    }
}

// ステートレスHMAC署名付きセッショントークンの生成 (st1.<payloadBase64Url>.<hmacHex>)
function createStatelessSessionToken(email, deviceUid, expiresAt)
{
    const cleanEmail = (email || '').trim().toLowerCase();
    const payloadObj = {
        email: cleanEmail,
        emailHash: sha256(cleanEmail),
        uid: (deviceUid || '').trim(),
        jti: crypto.randomBytes(12).toString('hex'),
        iat: Date.now(),
        exp: expiresAt
    };
    const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', SERVER_HMAC_SECRET).update(payloadB64).digest('hex');
    return `st1.${payloadB64}.${sig}`;
}

// ステートレスHMAC署名付きセッショントークンの検証・メモリ復元
function verifyAndRestoreStatelessToken(token)
{
    if (!token || typeof token !== 'string' || !token.startsWith('st1.')) { return null; }
    if (isTokenRevoked(token)) { return null; }
    const parts = token.split('.');
    if (parts.length !== 3) { return null; }
    const payloadB64 = parts[1];
    const sig = parts[2];
    // VULN-33是正: 未定義LEGACY_HMAC_SECRETを廃止し、Primary署名を厳格に検証
    const expectedPrimary = crypto.createHmac('sha256', SERVER_HMAC_SECRET).update(payloadB64).digest('hex');
    if (sig.length !== expectedPrimary.length || !crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expectedPrimary, 'utf8')))
    {
        return null;
    }
    try
    {
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
        if (!payload || !payload.uid || !payload.exp || payload.exp <= Date.now()) { return null; }
        if (isTokenRevoked(token, payload.jti || '')) { return null; }
        const restored = {
            email: payload.email || '',
            emailHash: payload.emailHash || sha256(payload.email || ''),
            deviceUid: payload.uid,
            jti: payload.jti || '',
            createdAt: payload.iat || Date.now(),
            expiresAt: payload.exp,
            lastExtendedAt: Date.now()
        };
        enforceMapSizeCap(activeSessions, 5000);
        activeSessions.set(token, restored);
        saveSessions();
        return restored;
    }
    catch (e)
    {
        return null;
    }
}

// セッショントークン＆物理端末UIDバインド厳格検証
function isValidSession(token, userId, slideExtension = true)
{
    if (!token || typeof token !== 'string') { return false; }
    if (isTokenRevoked(token))
    {
        activeSessions.delete(token);
        return false;
    }
    if (!activeSessions.has(token) && token.startsWith('st1.'))
    {
        verifyAndRestoreStatelessToken(token);
    }
    if (activeSessions.has(token))
    {
        const session = activeSessions.get(token);
        const now = Date.now();
        if (session && session.expiresAt > now && !isTokenRevoked(token, session.jti || ''))
        {
            if (session.deviceUid && userId && session.deviceUid !== userId)
            {
                console.warn(`[Security Block] 端末UID不一致によるセッション横取りを遮断: 発行元=${session.deviceUid}, 接続元=${userId}`);
                return false;
            }
            if (slideExtension && (now - (session.lastExtendedAt || 0) > 3600000))
            {
                session.expiresAt = now + SESSION_DURATION_MS;
                session.lastExtendedAt = now;
                saveSessions();
            }
            return true;
        }
        activeSessions.delete(token);
        saveSessions();
    }
    return false;
}

// HTTPヘッダーからBearerトークンを安全抽出
function extractBearerToken(req)
{
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer '))
    {
        return authHeader.slice(7).trim();
    }
    return '';
}

function loadOfflineQueue()
{
    try
    {
        const obj = readEncryptedJsonFile(QUEUE_FILE_PATH);
        if (!obj) { return; }
        for (const [userId, messages] of Object.entries(obj))
        {
            if (Array.isArray(messages) && messages.length > 0)
            {
                offlineMessageQueue.set(userId, messages);
            }
        }
        console.log(`[Offline Queue] ${offlineMessageQueue.size} ユーザー分のキューを復元完了`);
    }
    catch (err)
    {
        console.error('[Offline Queue Load Error]', err.message);
    }
}

let saveQueueTimer = null;
function saveOfflineQueue()
{
    if (saveQueueTimer) { clearTimeout(saveQueueTimer); }
    saveQueueTimer = setTimeout(() =>
    {
        const obj = {};
        for (const [userId, messages] of offlineMessageQueue.entries())
        {
            if (messages && messages.length > 0) { obj[userId] = messages; }
        }
        writeEncryptedJsonFile(QUEUE_FILE_PATH, obj);
    }, 200);
}


// VULN-34是正: 添付ファイルACLの暗号化永続化保存・復元
function saveAttachmentAcls()
{
    const obj = {};
    for (const [k, v] of attachmentAclStore.entries())
    {
        obj[k] = v;
    }
    writeEncryptedJsonFile(ATTACHMENT_ACLS_FILE, obj);
}

function loadAttachmentAcls()
{
    try
    {
        const obj = readEncryptedJsonFile(ATTACHMENT_ACLS_FILE);
        if (!obj) { return; }
        for (const [k, v] of Object.entries(obj))
        {
            if (v && v.uploaderUid)
            {
                attachmentAclStore.set(k, v);
            }
        }
        console.log(`[Attachment ACL Store] ${attachmentAclStore.size} 件のファイル認可情報を復元完了`);
    }
    catch (e)
    {
        console.error('[Attachment ACL Store] 復元エラー:', e.message);
    }
}

function saveFcmTokens()
{
    const obj = {};
    for (const [k, v] of fcmTokenStore.entries()) { obj[k] = v; }
    writeEncryptedJsonFile(FCM_TOKENS_FILE, obj);
}

function loadFcmTokens()
{
    try
    {
        const obj = readEncryptedJsonFile(FCM_TOKENS_FILE);
        if (!obj) { return; }
        for (const [k, v] of Object.entries(obj)) { fcmTokenStore.set(k, v); }
        console.log(`[FCM Store] ${fcmTokenStore.size} 件のFCMトークンを復元完了`);
    }
    catch (e)
    {
        console.error('[FCM Store] トークン復元エラー:', e.message);
    }
}

function saveOfflineReads()
{
    const obj = {};
    for (const [k, v] of offlineReadQueue.entries()) { obj[k] = v; }
    writeEncryptedJsonFile(OFFLINE_READS_FILE, obj);
}

function loadOfflineReads()
{
    try
    {
        const obj = readEncryptedJsonFile(OFFLINE_READS_FILE);
        if (!obj) { return; }
        for (const [k, v] of Object.entries(obj)) { offlineReadQueue.set(k, v); }
        console.log(`[Offline Read Store] ${offlineReadQueue.size} ユーザーの通知を復元完了`);
    }
    catch (e)
    {
        console.error('[Offline Read Store] 復元エラー:', e.message);
    }
}

// JSONリクエストボディの取得ヘルパー (最大5MB上限: OOM DoS完全防御)
function parseJsonBody(req, maxBytes = 5 * 1024 * 1024)
{
    return new Promise((resolve, reject) =>
    {
        let body = '';
        let received = 0;
        req.on('data', chunk =>
        {
            received += chunk.length;
            if (received > maxBytes)
            {
                req.destroy();
                return reject(new Error('Payload Too Large: JSONボディが上限(5MB)を超過しました'));
            }
            body += chunk;
        });
        req.on('end', () =>
        {
            try
            {
                resolve(body ? JSON.parse(body) : {});
            }
            catch (err)
            {
                reject(err);
            }
        });
        req.on('error', reject);
    });
}

// グレースフルシャットダウン用同期フラッシュ
function flushAllStoresSync()
{
    try
    {
        if (saveQueueTimer)
        {
            clearTimeout(saveQueueTimer);
            saveQueueTimer = null;
        }
        const queueObj = {};
        for (const [userId, messages] of offlineMessageQueue.entries())
        {
            if (messages && messages.length > 0) { queueObj[userId] = messages; }
        }
        writeEncryptedJsonFile(QUEUE_FILE_PATH, queueObj);
        saveSessions();
        saveRevokedTokens();
        saveFcmTokens();
        saveOfflineReads();
        saveAttachmentAcls();
        console.log('[Graceful Shutdown] 全永続化ストアの暗号化同期保存が完了しました');
    }
    catch (e)
    {
        console.error('[Graceful Shutdown Error]', e.message);
    }
}

// 起動時ロードと定期クリーンアップ開始
loadRevokedTokens();
loadSessions();
loadOfflineQueue();
loadFcmTokens();
loadOfflineReads();
loadAttachmentAcls();

setInterval(() =>
{
    const now = Date.now();
    for (const [email, entry] of otpStore.entries())
    {
        if (entry.expiresAt < now) { otpStore.delete(email); }
    }
    let sessionsChanged = false;
    for (const [token, session] of activeSessions.entries())
    {
        if (!session || session.expiresAt <= now || isTokenRevoked(token, session.jti || ''))
        {
            activeSessions.delete(token);
            sessionsChanged = true;
        }
    }
    if (sessionsChanged) { saveSessions(); }

    let revokedChanged = false;
    for (const [k, exp] of revokedTokens.entries())
    {
        if (!exp || exp <= now)
        {
            revokedTokens.delete(k);
            revokedChanged = true;
        }
    }
    if (revokedChanged) { saveRevokedTokens(); }

    for (const [ip, rec] of ipConnectionTracker.entries())
    {
        if (!rec || rec.resetTime < now) { ipConnectionTracker.delete(ip); }
    }
    for (const [pktKey, ts] of recentChatPacketIds.entries())
    {
        if (now - ts > 120000) { recentChatPacketIds.delete(pktKey); }
    }
}, 60000);

module.exports = {
    SERVER_DIR,
    ALLOWED_EMAIL_HASHES,
    APPROVAL_ROUTING,
    SESSION_DURATION_MS,
    fcmTokenStore,
    ipConnectionTracker,
    otpStore,
    activeSessions,
    revokedTokens,
    seenInviteNonces,
    emailOtpCooldownTracker,
    offlineMessageQueue,
    offlineReadQueue,
    attachmentAclStore,
    recentChatPacketIds,
    rooms,
    users,
    wsIpConnectionCount,
    enforceMapSizeCap,
    maskEmail,
    sha256,
    saveSessions,
    revokeSessionToken,
    isTokenRevoked,
    createStatelessSessionToken,
    verifyAndRestoreStatelessToken,
    isValidSession,
    extractBearerToken,
    saveOfflineQueue,
    saveFcmTokens,
    saveOfflineReads,
    saveAttachmentAcls,
    parseJsonBody,
    flushAllStoresSync
};

return module.exports;
})({ exports: {} }, {});

// ==================== [Module: ./modules/pushAndMail.js] ====================
__internalModules['./modules/pushAndMail'] = (function(module, exports) {
// 変更日時：2026年10月31日 12時14分
// [サーバーモジュール] Firebase Admin FCMプッシュ送信 ＆ OTP認証メール送信 (GAS / SMTP)

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SERVER_DIR } = __requireModule('./modules/stateStore');

let admin = null;
let firebaseApp = null;
try
{
    admin = require('firebase-admin');
    // VULN-38是正: ローカルファイル依存を完全撤廃し、環境変数 FIREBASE_SERVICE_ACCOUNT に一本化
    const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
        ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
        : null;

    if (serviceAccount && admin)
    {
        firebaseApp = admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log('[Firebase Admin] FCM プッシュ送信機能の初期化完了');
    }
}
catch (e)
{
    console.warn('[Firebase Admin Note] 初期化スキップまたは保留:', e.message);
}

let nodemailer = null;
try
{
    nodemailer = require('nodemailer');
}
catch (e)
{
    // nodemailer未導入時の安全フォールバック
}

// メールトランスポーターの初期化 (Gmail アプリパスワード連携)
function createMailTransporter()
{
    const user = process.env.GMAIL_USER;
    const pass = process.env.GMAIL_APP_PASS;
    if (!user || !pass || !nodemailer)
    {
        return null;
    }
    return nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: { user, pass },
        family: 4,
        connectionTimeout: 8000,
        greetingTimeout: 5000,
        socketTimeout: 10000
    });
}

// GAS (Google Apps Script) WebHook 経由でのメール送信 (Port 443 HTTPS通信: Render無料枠対応)
function sendMailViaGas(gasUrl, mailData)
{
    return new Promise((resolve, reject) =>
    {
        const postData = JSON.stringify(mailData);
        const parsedUrl = new URL(gasUrl);

        const options = {
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 15000
        };

        const req = https.request(options, (res) =>
        {
            if (res.statusCode === 302 || res.statusCode === 301 || res.statusCode === 307)
            {
                const redirectUrl = res.headers.location;
                if (!redirectUrl)
                {
                    return resolve({ success: true, redirected: true });
                }
                https.get(redirectUrl, (redirectRes) =>
                {
                    let body = '';
                    redirectRes.on('data', chunk => { body += chunk; });
                    redirectRes.on('end', () =>
                    {
                        try
                        {
                            resolve(JSON.parse(body));
                        }
                        catch (e)
                        {
                            resolve({ success: true, raw: body });
                        }
                    });
                }).on('error', (err) =>
                {
                    console.warn('[GAS Redirect Note]', err.message);
                    resolve({ success: true });
                });
                return;
            }

            let body = '';
            res.on('data', chunk => { body += chunk; });
            res.on('end', () =>
            {
                try
                {
                    resolve(JSON.parse(body));
                }
                catch (e)
                {
                    resolve({ success: res.statusCode >= 200 && res.statusCode < 300, raw: body });
                }
            });
        });

        req.on('timeout', () =>
        {
            req.destroy();
            reject(new Error('GASメール送信接続タイムアウト'));
        });

        req.on('error', reject);
        req.write(postData);
        req.end();
    });
}

// FCM高優先度着信データプッシュ送信
async function sendIncomingCallPush(targetFcmToken, callData)
{
    if (!firebaseApp || !admin)
    {
        console.warn('[FCM Push Warning] Firebase Admin未初期化のため着信プッシュをスキップ');
        return false;
    }
    if (!targetFcmToken)
    {
        console.warn('[FCM Push Warning] 宛先FCMトークン未登録のため着信プッシュ送信不可');
        return false;
    }
    try
    {
        const message = {
            token: targetFcmToken,
            data: {
                type: 'incoming_call',
                fromUserId: String(callData.fromUserId || ''),
                fromName: String(callData.fromName || '通話相手'),
                roomId: String(callData.roomId || ''),
                isVideo: String(callData.isVideo ? 'true' : 'false'),
                timestamp: String(Date.now()),
                nonce: crypto.randomBytes(8).toString('hex')
            },
            android: {
                priority: 'high',
                ttl: 60 * 1000
            }
        };

        const response = await admin.messaging().send(message);
        console.log(`[FCM Push] 着信データプッシュ送信完了 (${callData.fromName} -> Token: ${targetFcmToken.slice(0, 15)}...): ${response}`);
        return true;
    }
    catch (err)
    {
        console.error('[FCM Push Error] プッシュ送信失敗:', err.message);
        return false;
    }
}

// FCM新着チャットプッシュ送信 (dataメッセージ統一・暗号化本文＆添付ファイル情報を完全伝送)
async function sendChatMessagePush(targetFcmToken, chatData)
{
    if (!firebaseApp || !admin)
    {
        console.warn('[FCM Chat Push Warning] Firebase Admin未初期化のためチャットプッシュをスキップ');
        return false;
    }
    if (!targetFcmToken)
    {
        console.warn('[FCM Chat Push Warning] 宛先FCMトークン未登録のためチャットプッシュ送信不可');
        return false;
    }
    try
    {
        const message = {
            token: targetFcmToken,
            data: {
                type: 'chat_message',
                subType: String(chatData.subType || ''),
                targetMessageId: String(chatData.targetMessageId || ''),
                fromUserId: String(chatData.fromUserId || ''),
                fromName: String(chatData.fromName || '友だち'),
                messageId: String(chatData.messageId || ''),
                text: String(chatData.text || ''),
                iv: String(chatData.iv || ''),
                cipher: String(chatData.cipher || ''),
                // VULN-50是正: 4KB上限超過によるプッシュ送信エラーを完全防止
                hasImage: String(chatData.hasImage === 'true' || !!chatData.imageBase64 ? 'true' : 'false'),
                fileUrl: String(chatData.fileUrl || ''),
                // VULN-21是正: 添付ファイル復号鍵(fileKey)を平文プッシュ伝送から完全排除（E2EEペイロード内のみで安全に伝送）
                fileKey: '',
                fileName: String(chatData.fileName || ''),
                fileSize: String(chatData.fileSize || '0'),
                senderPubKey: String(chatData.senderPubKey || ''),
                // VULN-24是正: 電子署名(senderPubSig)を正しく伝送し、FCMプッシュ経由での鍵検証を可能にする
                senderPubSig: String(chatData.senderPubSig || ''),
                timestamp: String(chatData.timestamp || Date.now())
            },
            android: {
                priority: 'high',
                ttl: 7 * 24 * 60 * 60 * 1000
            }
        };

        const response = await admin.messaging().send(message);
        console.log(`[FCM Chat Push] 新着チャットデータプッシュ送信完了 (${chatData.fromName} -> Token: ${targetFcmToken.slice(0, 15)}...): ${response}`);
        return true;
    }
    catch (err)
    {
        console.error('[FCM Chat Push Error] チャットプッシュ送信失敗:', err.message);
        return false;
    }
}

module.exports = {
    createMailTransporter,
    sendMailViaGas,
    sendIncomingCallPush,
    sendChatMessagePush
};

return module.exports;
})({ exports: {} }, {});

// ==================== [Module: ./modules/httpAuthRoutes.js] ====================
__internalModules['./modules/httpAuthRoutes'] = (function(module, exports) {
// 変更日時：2026年10月31日 12時16分
// [サーバーモジュール] 二段階認証OTP・セッション管理・FCMデバイストークン登録HTTPルート

const crypto = require('crypto');
const {
    ALLOWED_EMAIL_HASHES,
    APPROVAL_ROUTING,
    SESSION_DURATION_MS,
    fcmTokenStore,
    otpStore,
    activeSessions,
    emailOtpCooldownTracker,
    enforceMapSizeCap,
    maskEmail,
    sha256,
    saveSessions,
    revokeSessionToken,
    isTokenRevoked,
    createStatelessSessionToken,
    verifyAndRestoreStatelessToken,
    isValidSession,
    extractBearerToken,
    saveFcmTokens,
    parseJsonBody
} = __requireModule('./modules/stateStore');
const { createMailTransporter, sendMailViaGas } = __requireModule('./modules/pushAndMail');

// 認証およびFCM登録系HTTPエンドポイントの処理 (処理した場合は true を返す)
async function handleAuthRoutes(req, res, url)
{
    // [API 1] OTP送信: POST /api/auth/send-otp
    if (req.method === 'POST' && url === '/api/auth/send-otp')
    {
        try
        {
            const body = await parseJsonBody(req);
            const email = (body.email || '').trim().toLowerCase();

            if (!email)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'メールアドレスが指定されていません' }));
                return true;
            }

            const emailHash = sha256(email);
            if (!ALLOWED_EMAIL_HASHES.has(emailHash))
            {
                console.warn(`[Auth Warning] 未許可メールアドレスのOTP要求を遮断: ${email} (${emailHash})`);
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'このGoogleアカウントはアクセス許可リストに存在しません' }));
                return true;
            }

            const now = Date.now();
            const lastSent = emailOtpCooldownTracker.get(email) || 0;
            if (now - lastSent < 60000)
            {
                const remainSec = Math.ceil((60000 - (now - lastSent)) / 1000);
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: `認証コードは送信済みです。再送信まであと ${remainSec} 秒お待ちください` }));
                return true;
            }
            enforceMapSizeCap(emailOtpCooldownTracker, 2000);
            emailOtpCooldownTracker.set(email, now);

            const code = crypto.randomInt(100000, 1000000).toString();
            const expiresAt = now + 5 * 60 * 1000;
            enforceMapSizeCap(otpStore, 2000);
            otpStore.set(email, { code, expiresAt, attempts: 0, lastSentAt: now });

            const targetEmail = APPROVAL_ROUTING[email] || email;
            const maskedTarget = maskEmail(targetEmail);
            const maskedCode = `${code.slice(0, 2)}****`;

            console.log(`[Cross-Auth OTP] ログイン試行: ${email} -> 承認コード送信先: ${targetEmail} (${maskedCode})`);

            const mailSubject = `【CellPhone App】${email} からのログイン承認要求`;
            const mailText = `CellPhone App にて「${email}」がログインを試行しています。\n\n心当たりがある場合は、以下の6桁の承認コードをLINE等で相手にお伝えください。\n\n承認コード: ${code}\n\n※このコードの有効期限は5分間です。\n※心当たりのない場合は絶対に他人にコードを教えないでください。`;
            const mailHtml = `
                <div style="font-family: sans-serif; max-width: 500px; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #3B82F6; margin-top: 0;">CellPhone App 相互承認要求</h2>
                    <p><strong>「${email}」</strong> がアプリへのサインインを試行しています。</p>
                    <p>ご本人からの連絡であることを確認した上で、以下の承認コードを<strong>LINE等</strong>でお伝えください。</p>
                    <div style="background-color: #EFF6FF; padding: 15px; border-radius: 6px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1D4ED8; margin: 20px 0; border: 1px dashed #93C5FD;">
                        ${code}
                    </div>
                    <p style="font-size: 13px; color: #6B7280;">※この承認コードの有効期限は<strong>5分間</strong>です。<br>※身に覚えのない場合は絶対にコードを伝えないでください。</p>
                </div>
            `;

            const gasUrl = process.env.GAS_MAIL_URL;
            if (gasUrl)
            {
                try
                {
                    console.log(`[GAS Mail] 送信開始: ${targetEmail} via ${gasUrl.slice(0, 45)}...`);
                    await sendMailViaGas(gasUrl, {
                        to: targetEmail,
                        subject: mailSubject,
                        text: mailText,
                        html: mailHtml
                    });
                    console.log(`[GAS Mail] 送信成功: ${targetEmail}`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        message: `承認コードを「${maskedTarget}」宛てに送信しました。\n相手の方からLINE等でコードを受け取ってください。`,
                        targetNotice: maskedTarget
                    }));
                    return true;
                }
                catch (gasErr)
                {
                    console.error('[GAS Mail Error]', gasErr);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'GASメール送信エラー: ' + gasErr.message }));
                    return true;
                }
            }

            const transporter = createMailTransporter();
            if (transporter)
            {
                const mailOptions = {
                    from: `"CellPhone App 相互承認" <${process.env.GMAIL_USER}>`,
                    to: targetEmail,
                    subject: mailSubject,
                    text: mailText,
                    html: mailHtml
                };

                await transporter.sendMail(mailOptions);
                console.log(`[Cross-Auth OTP Email] 送信完了: ${targetEmail}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    message: `承認コードを「${maskedTarget}」宛てに送信しました。\n相手の方からLINE等でコードを受け取ってください。`,
                    targetNotice: maskedTarget
                }));
            }
            else
            {
                console.error('[OTP Error] GMAIL_USER/GAS_MAIL_URL が未設定のため認証コードを送信できません');
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: false,
                    error: 'メール送信設定が未構成のため認証コードを発行できません。管理者へお問い合わせください。'
                }));
            }
            return true;
        }
        catch (err)
        {
            console.error('[OTP Send Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '認証コード送信中にエラーが発生しました: ' + err.message }));
            return true;
        }
    }

    // [API 2] OTP検証: POST /api/auth/verify-otp
    if (req.method === 'POST' && url === '/api/auth/verify-otp')
    {
        try
        {
            const body = await parseJsonBody(req);
            const email = (body.email || '').trim().toLowerCase();
            const inputCode = (body.code || '').trim();

            const entry = otpStore.get(email);
            if (!entry)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードが発行されていないか、有効期限が切れています' }));
                return true;
            }

            if (entry.expiresAt < Date.now())
            {
                otpStore.delete(email);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードの有効期限が切れました。再送信してください' }));
                return true;
            }

            entry.attempts++;
            if (entry.attempts > 5)
            {
                otpStore.delete(email);
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証試行回数の上限を超えました。コードを再発行してください' }));
                return true;
            }

            if (inputCode.length !== 6 || entry.code.length !== 6)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードは6桁の数字です' }));
                return true;
            }

            const codeMatch = crypto.timingSafeEqual(
                Buffer.from(entry.code, 'utf8'),
                Buffer.from(inputCode, 'utf8')
            );

            if (!codeMatch)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードが一致しません' }));
                return true;
            }

            otpStore.delete(email);

            const deviceUid = (body.deviceUid || '').trim();
            if (!deviceUid || !/^u_[a-zA-Z0-9]{8,40}$/.test(deviceUid))
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '端末固有識別子(deviceUid)が不正です' }));
                return true;
            }

            const expiresAt = Date.now() + SESSION_DURATION_MS;
            const sessionToken = createStatelessSessionToken(email, deviceUid, expiresAt);
            enforceMapSizeCap(activeSessions, 5000);
            activeSessions.set(sessionToken, {
                email,
                emailHash: sha256(email),
                deviceUid,
                createdAt: Date.now(),
                expiresAt,
                lastExtendedAt: Date.now()
            });
            saveSessions();

            console.log(`[Auth Success] 認証完了: ${email} (端末: ${deviceUid}) -> ステートレスHMACセッショントークン発行`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                sessionToken: sessionToken,
                email: email,
                expiresAt: expiresAt
            }));
            return true;
        }
        catch (err)
        {
            console.error('[OTP Verify Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '内部認証処理エラー: ' + err.message }));
            return true;
        }
    }

    // [API 2.5] ログアウト: POST /api/auth/logout (No.03: ステートレスst1.トークンもブラックリスト登録して完全失効)
    if (req.method === 'POST' && url === '/api/auth/logout')
    {
        const token = extractBearerToken(req);
        if (token)
        {
            revokeSessionToken(token);
            console.log(`[Auth Logout] セッショントークンをブラックリストに登録し完全失効させました`);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'ログアウトしました' }));
        return true;
    }

    // [API 2.6] セッショントークン裏更新: POST /api/auth/refresh
    if (req.method === 'POST' && url === '/api/auth/refresh')
    {
        const token = extractBearerToken(req);
        const deviceUid = (req.headers['x-device-uid'] || '').trim();
        if (token && isValidSession(token, deviceUid, true))
        {
            let session = activeSessions.get(token);
            if (!session && token.startsWith('st1.'))
            {
                session = verifyAndRestoreStatelessToken(token);
            }
            if (!session)
            {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'セッション情報の復元に失敗しました' }));
                return true;
            }

            const newExpiresAt = Date.now() + SESSION_DURATION_MS;
            const effUid = session.deviceUid || deviceUid;
            const newToken = createStatelessSessionToken(session.email, effUid, newExpiresAt);

            // VULN-35是正: 旧トークンを失効リストへ即時登録しゾンビセッション化を完全防止
            revokeSessionToken(token);
            activeSessions.delete(token);

            enforceMapSizeCap(activeSessions, 5000);
            activeSessions.set(newToken, {
                email: session.email,
                emailHash: session.emailHash || sha256(session.email || ''),
                deviceUid: effUid,
                createdAt: session.createdAt || Date.now(),
                expiresAt: newExpiresAt,
                lastExtendedAt: Date.now()
            });
            saveSessions();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                message: 'セッションを3日間自動延長しました',
                sessionToken: newToken,
                expiresAt: newExpiresAt
            }));
            return true;
        }
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'セッションが無効または失効しています' }));
        return true;
    }

    // [API 2.7] サーバー再起動・スリープ時の認証済みセッション自動復旧: POST /api/auth/rebind-session
    // No.01対策: oldTokenのHMAC署名・失効状態・UID・メールアドレス一致を厳格検証し、未認証なりすましを100%遮断
    if (req.method === 'POST' && url === '/api/auth/rebind-session')
    {
        try
        {
            const body = await parseJsonBody(req);
            const email = (body.email || '').trim().toLowerCase();
            const deviceUid = (body.deviceUid || '').trim();
            const oldToken = extractBearerToken(req) || (body.sessionToken || '').trim();

            if (!email || !deviceUid || !/^u_[a-zA-Z0-9]{8,40}$/.test(deviceUid))
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'パラメータが不正です' }));
                return true;
            }

            const emailHash = sha256(email);
            if (!ALLOWED_EMAIL_HASHES.has(emailHash))
            {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '未許可アカウントです' }));
                return true;
            }

            if (!oldToken || isTokenRevoked(oldToken))
            {
                console.warn(`[Security Block] 未指定または失効済みトークンによるセッション再バインド要求を遮断: email=${email}, uid=${deviceUid}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '既存セッションが無効または失効しています。再ログインしてください' }));
                return true;
            }

            let ownerVerified = false;
            let existingSession = null;

            if (isValidSession(oldToken, deviceUid, false))
            {
                existingSession = activeSessions.get(oldToken);
            }
            else if (oldToken.startsWith('st1.'))
            {
                // VULN-25是正: ステートレスHMAC署名を厳格に検証（偽装署名・改ざんトークンを完全排除）
                existingSession = verifyAndRestoreStatelessToken(oldToken);
            }

            if (existingSession)
            {
                const existingEmailHash = existingSession.emailHash || sha256(existingSession.email || '');
                if ((!existingEmailHash || existingEmailHash === emailHash) && existingSession.deviceUid === deviceUid)
                {
                    ownerVerified = true;
                }
            }

            if (!ownerVerified)
            {
                console.warn(`[Security Block] 不正署名または所有者が異なるトークンでの再バインドを遮断: uid=${deviceUid}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'セッションの署名検証に失敗したか、所有者情報が一致しません' }));
                return true;
            }

            // VULN-16是正: 旧トークンを失効リストに登録して即時無効化（ゾンビセッション化防止）
            revokeSessionToken(oldToken);
            activeSessions.delete(oldToken);

            const expiresAt = Date.now() + SESSION_DURATION_MS;
            const newToken = createStatelessSessionToken(email, deviceUid, expiresAt);
            const sessionObj = {
                email,
                emailHash,
                deviceUid,
                createdAt: existingSession?.createdAt || Date.now(),
                expiresAt,
                lastExtendedAt: Date.now()
            };
            enforceMapSizeCap(activeSessions, 5000);
            activeSessions.set(newToken, sessionObj);
            saveSessions();

            console.log(`[Session Rebind] 認証済みセッションを安全に更新: ${email} (UID: ${deviceUid})`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                sessionToken: newToken,
                expiresAt: expiresAt
            }));
            return true;
        }
        catch (err)
        {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return true;
        }
    }

    // [API 3] FCMデバイストークン登録: POST /api/user/fcm-token
    if (req.method === 'POST' && url === '/api/user/fcm-token')
    {
        try
        {
            const body = await parseJsonBody(req);
            const userId = (body.userId || '').trim();
            const email = (body.email || '').trim().toLowerCase();
            const fcmToken = (body.fcmToken || '').trim();
            const token = extractBearerToken(req) || (body.token || '').trim();

            if (!userId || !fcmToken)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'userIdまたはfcmTokenが不正です' }));
                return true;
            }

            if (!token || !isValidSession(token, userId))
            {
                console.warn(`[Security Block] 未認証または不正トークンによるFCM登録を拒絶: ${userId}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
                return true;
            }

            enforceMapSizeCap(fcmTokenStore, 5000);
            fcmTokenStore.set(userId, { fcmToken, email, updatedAt: Date.now() });
            saveFcmTokens();
            console.log(`[FCM Token] 登録成功: ${userId} (${email}) -> ${fcmToken.slice(0, 15)}...`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
            return true;
        }
        catch (err)
        {
            console.error('[FCM Token Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return true;
        }
    }

    return false;
}

module.exports = {
    handleAuthRoutes
};

return module.exports;
})({ exports: {} }, {});

// ==================== [Module: ./modules/httpChatAndFileRoutes.js] ====================
__internalModules['./modules/httpChatAndFileRoutes'] = (function(module, exports) {
// 変更日時：2026年10月31日 12時12分
// [サーバーモジュール] チャット保留取得・既読・メッセージ送信・暗号化ファイル転送HTTPルート

const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
    SERVER_DIR,
    fcmTokenStore,
    activeSessions,
    offlineMessageQueue,
    offlineReadQueue,
    attachmentAclStore,
    recentChatPacketIds,
    users,
    enforceMapSizeCap,
    isValidSession,
    verifyAndRestoreStatelessToken,
    extractBearerToken,
    saveOfflineQueue,
    saveOfflineReads,
    saveAttachmentAcls,
    parseJsonBody
} = __requireModule('./modules/stateStore');
const { sendChatMessagePush } = __requireModule('./modules/pushAndMail');

const UPLOAD_DIR = path.join(SERVER_DIR, 'uploads');

// チャットおよび暗号化ファイル系HTTPエンドポイントの処理 (処理した場合は true を返す)
async function handleChatAndFileRoutes(req, res, url)
{
    const parsedReqUrl = new URL(url, 'http://localhost');

    // [API 4] 保留チャットメッセージ一括取得
    if (req.method === 'GET' && parsedReqUrl.pathname === '/api/chat/pending')
    {
        try
        {
            const targetUserId = (parsedReqUrl.searchParams.get('userId') || '').trim();
            const token = extractBearerToken(req) || (parsedReqUrl.searchParams.get('token') || '').trim();

            if (!targetUserId)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'userIdが指定されていません' }));
                return true;
            }

            if (!token || !isValidSession(token, targetUserId))
            {
                console.warn(`[Security Block] 未認証または不正トークンによる保留メッセージ取得を遮断: ${targetUserId}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
                return true;
            }

            const messages = offlineMessageQueue.get(targetUserId) || [];
            offlineMessageQueue.delete(targetUserId);
            saveOfflineQueue();

            const readReceipts = offlineReadQueue.get(targetUserId) || [];
            offlineReadQueue.delete(targetUserId);
            saveOfflineReads();

            console.log(`[Chat Pending API] ${targetUserId} へ保留メッセージ ${messages.length}件、既読通知 ${readReceipts.length}バッチを一括返却・クリア`);
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: true,
                userId: targetUserId,
                count: messages.length,
                messages: messages,
                readReceipts: readReceipts
            }));
            return true;
        }
        catch (err)
        {
            console.error('[Chat Pending API Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return true;
        }
    }

    // [API 5] 既読通知受信: POST /api/chat/read
    if (req.method === 'POST' && url === '/api/chat/read')
    {
        try
        {
            const body = await parseJsonBody(req);
            const fromUserId = (body.fromUserId || '').trim();
            const targetUserId = (body.targetUserId || '').trim();
            const messageIds = Array.isArray(body.messageIds) ? body.messageIds : [];
            const token = extractBearerToken(req) || (body.token || '').trim();

            if (!fromUserId || !targetUserId || messageIds.length === 0)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '引数が不足しています' }));
                return true;
            }

            if (!token || !isValidSession(token, fromUserId))
            {
                console.warn(`[Security Block] 未認証または不正トークンによる既読送信を遮断: ${fromUserId}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
                return true;
            }

            const targetEntry = users.get(targetUserId);
            let forwarded = false;
            if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
            {
                targetEntry.ws.send(JSON.stringify({
                    type: 'chat_read',
                    fromUserId: fromUserId,
                    targetUserId: targetUserId,
                    messageIds: messageIds
                }));
                forwarded = true;
                console.log(`[HTTP Chat Read] ${fromUserId} が ${targetUserId} のメッセージ ${messageIds.length}件を既読 (WS即時中継)`);
            }

            if (!offlineReadQueue.has(targetUserId))
            {
                offlineReadQueue.set(targetUserId, []);
            }
            const rq = offlineReadQueue.get(targetUserId);
            rq.push({
                fromUserId: fromUserId,
                targetUserId: targetUserId,
                messageIds: messageIds,
                timestamp: Date.now()
            });
            if (rq.length > 300) { rq.shift(); }
            saveOfflineReads();
            console.log(`[HTTP Chat Read Store] 相手(${targetUserId})宛ての既読通知をキュー二重保持 (保留計: ${rq.length}件, WS即時=${forwarded})`);

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, forwarded: forwarded }));
            return true;
        }
        catch (err)
        {
            console.error('[HTTP Chat Read Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return true;
        }
    }

    // [API 6] チャットメッセージ送信: POST /api/chat/send
    if (req.method === 'POST' && url === '/api/chat/send')
    {
        try
        {
            const data = await parseJsonBody(req);
            const fromUserId = (data.fromUserId || '').trim();
            const targetUserId = (data.targetUserId || data.targetId || '').trim();
            const pktType = data.type || 'chat_message';
            const isKeyPacket = (pktType === 'chat_key_ping' || pktType === 'chat_key_pong');
            const token = extractBearerToken(req) || (data.token || '').trim();

            if (!fromUserId || !targetUserId || (!isKeyPacket && !data.messageId))
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '引数が不足しています' }));
                return true;
            }

            if (!token || !isValidSession(token, fromUserId))
            {
                console.warn(`[Security Block] 未認証または不正トークンによるメッセージ送信を遮断: ${fromUserId}`);
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
                return true;
            }

            const targetEntry = users.get(targetUserId);
            const senderName = users.get(fromUserId)?.name || data.fromName || '友だち';
            const isMutation = (data.subType === 'unsend' || data.subType === 'edit');
            const dedupKey = data.messageId ? `${fromUserId}:${targetUserId}:${data.messageId}` : '';
            const alreadyProcessed = dedupKey ? recentChatPacketIds.has(dedupKey) : false;
            if (dedupKey)
            {
                enforceMapSizeCap(recentChatPacketIds, 5000);
                recentChatPacketIds.set(dedupKey, Date.now());
            }

            let sentViaWs = false;
            if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
            {
                if (!alreadyProcessed)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                    console.log(`[HTTP Chat] Forwarded message from ${fromUserId} to ${targetUserId} via WebSocket (subType=${data.subType || 'normal'})`);
                }
                sentViaWs = true;
            }

            // オフライン時、または送信取消・書換え(unsend/edit)時はハーフオープン対策として必ずキュー側にも反映 (No.17対策)
            if (!sentViaWs || isMutation)
            {
                if (!offlineMessageQueue.has(targetUserId))
                {
                    enforceMapSizeCap(offlineMessageQueue, 500);
                    offlineMessageQueue.set(targetUserId, []);
                }
                const queue = offlineMessageQueue.get(targetUserId);
                if (data.subType === 'unsend' && data.targetMessageId)
                {
                    for (let i = queue.length - 1; i >= 0; i--)
                    {
                        if ((queue[i].messageId === data.targetMessageId || queue[i].targetMessageId === data.targetMessageId) && queue[i].fromUserId === fromUserId)
                        {
                            queue.splice(i, 1);
                        }
                    }
                }
                else if (data.subType === 'edit' && data.targetMessageId)
                {
                    for (let i = queue.length - 1; i >= 0; i--)
                    {
                        if (queue[i].subType === 'edit' && queue[i].targetMessageId === data.targetMessageId && queue[i].fromUserId === fromUserId)
                        {
                            queue.splice(i, 1);
                        }
                    }
                }
                if (!queue.some(m => m.messageId && m.messageId === data.messageId))
                {
                    queue.push(data);
                    if (queue.length > 100) { queue.shift(); }
                    saveOfflineQueue();
                    console.log(`[HTTP Chat Queue] 相手(${targetUserId})宛てキュー保管完了 (subType=${data.subType || 'normal'}, 保留計: ${queue.length}件)`);
                }
            }

            const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get(targetUserId.trim());
            if (!isKeyPacket && !alreadyProcessed && targetFcm && targetFcm.fcmToken)
            {
                sendChatMessagePush(targetFcm.fcmToken, {
                    subType: data.subType || '',
                    targetMessageId: data.targetMessageId || '',
                    fromUserId: fromUserId,
                    fromName: senderName,
                    messageId: data.messageId,
                    text: data.text || '',
                    iv: data.iv || '',
                    cipher: data.cipher || '',
                    // VULN-50是正: FCM 4KBペイロード制限超過を防ぐため生画像Base64を除外
                    hasImage: data.imageBase64 ? 'true' : '',
                    fileUrl: data.fileUrl || '',
                    fileKey: '',
                    fileName: data.fileName || '',
                    fileSize: data.fileSize || '0',
                    senderPubKey: data.senderPubKey || '',
                    senderPubSig: data.senderPubSig || '',
                    timestamp: data.timestamp || Date.now()
                });
            }

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, messageId: data.messageId, sentViaWs: sentViaWs }));
            return true;
        }
        catch (err)
        {
            console.error('[HTTP Chat Send API Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return true;
        }
    }

    // [API 7] 暗号化ファイル直接アップロード: POST /api/file/upload (No.11: ACL記録＆UID別クォータ制限)
    if (req.method === 'POST' && url === '/api/file/upload')
    {
        try
        {
            const token = extractBearerToken(req);
            if (!token || !isValidSession(token))
            {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
                return true;
            }

            const session = activeSessions.get(token);
            const uploaderUid = (session?.deviceUid || '').trim();
            const targetUid = (req.headers['x-target-uid'] || '').trim();

            // 1ユーザーあたりの同時保持ファイル数・合計容量クォータ検証 (最大30ファイルまたは300MBまで)
            if (uploaderUid)
            {
                let userFileCount = 0;
                let userTotalBytes = 0;
                for (const meta of attachmentAclStore.values())
                {
                    if (meta.uploaderUid === uploaderUid)
                    {
                        userFileCount++;
                        userTotalBytes += (meta.size || 0);
                    }
                }
                if (userFileCount >= 30 || userTotalBytes > 300 * 1024 * 1024)
                {
                    res.writeHead(429, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: '一時ファイル保持上限に達しました。しばらく待ってから再試行してください' }));
                    return true;
                }
            }

            if (!fs.existsSync(UPLOAD_DIR))
            {
                fs.mkdirSync(UPLOAD_DIR, { recursive: true });
            }

            const fileId = 'enc_' + crypto.randomBytes(16).toString('hex');
            const savePath = path.join(UPLOAD_DIR, `${fileId}.bin`);
            const writeStream = fs.createWriteStream(savePath, { mode: 0o600 });

            let uploadedBytes = 0;
            let isAborted = false;
            const maxLimit = 150 * 1024 * 1024;

            req.on('data', (chunk) => {
                if (isAborted) { return; }
                uploadedBytes += chunk.length;
                if (uploadedBytes > maxLimit)
                {
                    isAborted = true;
                    req.unpipe(writeStream);
                    writeStream.destroy();
                    try { if (fs.existsSync(savePath)) { fs.unlinkSync(savePath); } } catch (e) {}
                    if (!res.headersSent)
                    {
                        res.writeHead(413, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'ファイルサイズが上限(150MB)を超えています' }));
                    }
                    req.destroy();
                }
            });

            req.pipe(writeStream);

            writeStream.on('finish', () => {
                if (isAborted || res.headersSent) { return; }
                enforceMapSizeCap(attachmentAclStore, 2000);
                attachmentAclStore.set(fileId, {
                    uploaderUid: uploaderUid,
                    targetUid: targetUid,
                    size: uploadedBytes,
                    createdAt: Date.now()
                });
                const rawHost = (req.headers['host'] || 'cellphone-signaling-server.onrender.com').trim();
                const safeHost = /^[a-zA-Z0-9.-]+(:\d{1,5})?$/.test(rawHost) ? rawHost : 'cellphone-signaling-server.onrender.com';
                const rawProto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
                const protocol = (rawProto === 'https' || rawProto === 'http') ? rawProto : (req.socket.encrypted ? 'https' : 'https');
                const downloadUrl = `${protocol}://${safeHost}/api/file/download/${fileId}`;
                console.log(`[File Upload] 暗号化ファイルを正常保管: ${fileId} (${uploadedBytes} bytes, from=${uploaderUid}, to=${targetUid || 'any'})`);
                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({
                    success: true,
                    fileId: fileId,
                    url: downloadUrl,
                    size: uploadedBytes
                }));
            });

            writeStream.on('error', (err) => {
                if (isAborted || res.headersSent) { return; }
                isAborted = true;
                console.error('[File Upload Error]', err);
                try { if (fs.existsSync(savePath)) { fs.unlinkSync(savePath); } } catch (e) {}
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'ファイル書き込みエラー: ' + err.message }));
            });
            return true;
        }
        catch (err)
        {
            console.error('[File Upload Exception]', err);
            if (!res.headersSent)
            {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: err.message }));
            }
            return true;
        }
    }

    // [API 8] 暗号化ファイル直接ダウンロード: GET /api/file/download/*
    if (req.method === 'GET' && url.startsWith('/api/file/download/'))
    {
        const token = extractBearerToken(req);
        if (!token || !isValidSession(token))
        {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '認証セッションが無効または未指定です' }));
            return true;
        }

        const urlPath = url.split('?')[0];
        const fileId = path.basename(urlPath);
        if (!/^enc_[a-f0-9]{32}$/.test(fileId))
        {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '無効なファイル識別子です' }));
            return true;
        }

// VULN-04 & VULN-28 是正: 送信者または指定受信者以外の第三者によるダウンロード(IDOR)を完全遮断
        let session = activeSessions.get(token);
        if (!session && token.startsWith('st1.'))
        {
            session = verifyAndRestoreStatelessToken(token);
        }
        const requesterUid = (session?.deviceUid || '').trim();
        const acl = attachmentAclStore.get(fileId);
        if (acl)
        {
            if (!requesterUid)
            {
                console.warn(`[Security Block] 未認証またはUID特定不能なダウンロード要求を遮断: ${fileId}`);
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'アクセス権限がありません' }));
                return true;
            }
            const isUploader = (acl.uploaderUid && requesterUid === acl.uploaderUid);
            const isTarget = (acl.targetUid && requesterUid === acl.targetUid);
            if (!isUploader && !isTarget)
            {
                console.warn(`[Security Block] 権限のないユーザー(${requesterUid})による添付ファイル(${fileId})取得を遮断 (uploader=${acl.uploaderUid}, target=${acl.targetUid})`);
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'このファイルへのアクセス権限がありません' }));
                return true;
            }
        }
        else
        {
            console.warn(`[Security Block] ACL情報が存在しない添付ファイル(${fileId})へのダウンロード要求を安全のため遮断`);
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'ファイルのアクセス権限が見つかりません' }));
            return true;
        }

        const filePath = path.join(UPLOAD_DIR, `${fileId}.bin`);
        if (!fs.existsSync(filePath))
        {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('File not found or expired');
            return true;
        }

        const stat = fs.statSync(filePath);
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': stat.size,
            'Content-Disposition': `attachment; filename="${fileId}.bin"`,
            'Cache-Control': 'no-cache'
        });
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
        return true;
    }

    return false;
}

// アップロードファイルの定期クリーンアップ (24時間超過した一時暗号化ファイルを自動消去)
setInterval(() =>
{
    try
    {
        if (fs.existsSync(UPLOAD_DIR))
        {
            const now = Date.now();
            const TTL_MS = 24 * 60 * 60 * 1000;
            const files = fs.readdirSync(UPLOAD_DIR);
            for (const f of files)
            {
                if (f.startsWith('enc_') && f.endsWith('.bin'))
                {
                    const fp = path.join(UPLOAD_DIR, f);
                    const stat = fs.statSync(fp);
                    if (now - stat.mtimeMs > TTL_MS)
                    {
                        fs.unlinkSync(fp);
                        attachmentAclStore.delete(f.slice(0, -4));
                        saveAttachmentAcls();
                        console.log(`[File Cleanup] 期限切れ一時暗号化ファイルを自動消去: ${f}`);
                    }
                }
            }
        }
    }
    catch (e)
    {
        console.error('[File Cleanup Error]', e.message);
    }
}, 3600000);

module.exports = {
    handleChatAndFileRoutes
};

return module.exports;
})({ exports: {} }, {});

// ==================== [Module: ./modules/wsSignaling.js] ====================
__internalModules['./modules/wsSignaling'] = (function(module, exports) {
// 変更日時：2026年10月31日 12時18分
// [サーバーモジュール] WebSocket P2P通話シグナリング ＆ E2EEチャット・既読リアルタイム中継

const WebSocket = require('ws');
const {
    fcmTokenStore,
    seenInviteNonces,
    offlineMessageQueue,
    offlineReadQueue,
    recentChatPacketIds,
    rooms,
    users,
    wsIpConnectionCount,
    enforceMapSizeCap,
    isValidSession,
    saveOfflineQueue,
    saveOfflineReads
} = __requireModule('./modules/stateStore');
const { sendIncomingCallPush, sendChatMessagePush } = __requireModule('./modules/pushAndMail');

// ルームからの退出処理
function removeClientFromRoom(ws, roomId, userId) {
    if (!roomId || !rooms.has(roomId)) { return; }
    const room = rooms.get(roomId);
    let target = null;
    room.forEach((client) => {
        if (client.ws === ws) { target = client; }
    });

    if (target) {
        room.delete(target);
        console.log(`[Leave] Room: ${roomId}, User: ${userId}, Remaining: ${room.size}`);
        room.forEach((client) => {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({ type: 'left', peerId: userId }));
            }
        });
    }

    if (room.size === 0) {
        rooms.delete(roomId);
    }
}

// WebSocketサーバーの初期化と全イベントバインド
function setupWebSocketServer(server) {
    const wss = new WebSocket.Server({ server, maxPayload: 512 * 1024 });

    // 25秒間隔のハートビートPing
    const heartbeatInterval = setInterval(() => {
        wss.clients.forEach((ws) => {
            if (ws.isAlive === false) {
                return ws.terminate();
            }
            ws.isAlive = false;
            ws.ping();
        });
    }, 25000);

    wss.on('close', () => {
        clearInterval(heartbeatInterval);
    });

    wss.on('connection', (ws, req) => {
        const rawForwarded = req?.headers?.['x-forwarded-for'];
        const wsClientIp = (rawForwarded ? rawForwarded.split(',')[0].trim() : null) || req?.socket?.remoteAddress || 'unknown';
        const currentIpConns = wsIpConnectionCount.get(wsClientIp) || 0;
        if (currentIpConns >= 15) {
            console.warn(`[WS DoS Block] 同一IPからの同時接続上限(15)超過を遮断: ${wsClientIp}`);
            ws.close(1008, 'Too many connections from this IP');
            return;
        }
        wsIpConnectionCount.set(wsClientIp, currentIpConns + 1);

        ws.isAlive = true;
        ws.on('pong', () => { ws.isAlive = true; });

        let currentRoomId = null;
        let currentUserId = null;

        const unauthTimeout = setTimeout(() => {
            if (!currentUserId && ws.readyState === WebSocket.OPEN) {
                console.warn(`[WS Unauth Timeout] 15秒間未認証のソケットを強制切断: ${wsClientIp}`);
                ws.close(4001, 'Authentication timeout');
            }
        }, 15000);

        ws.rateLimitWindowStart = Date.now();
        ws.messageCountInWindow = 0;

        ws.on('message', (message) => {
            try {
                // VULN-48是正: 巨大パケットの同期JSONパースによるイベントループブロッキングDoSを遮断
                if (message.length > 512 * 1024) {
                    console.warn(`[Security Block] 許容サイズ(512KB)超過のWebSocketパケットを遮断: size=${message.length}`);
                    ws.close(1009, 'Message too big');
                    return;
                }

                const now = Date.now();
                if (now - ws.rateLimitWindowStart > 1000) {
                    ws.rateLimitWindowStart = now;
                    ws.messageCountInWindow = 0;
                }
                ws.messageCountInWindow++;
                if (ws.messageCountInWindow > 30) {
                    console.warn(`[Rate Limit Exceeded] メッセージ過剰送信をドロップ: ${currentUserId || 'unknown'}`);
                    return;
                }

                const data = JSON.parse(message);
                const type = data.type;
                const roomId = data.roomId;
                const userId = data.userId;
                const token = data.token;

                // 1. 待受登録
                if (type === 'register') {
                    if (!isValidSession(token, userId)) {
                        console.warn(`[Security Block] 不正または未認証セッションによる待受登録を拒否: ${userId}`);
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'auth_error', message: '認証セッションが無効です。再ログインしてください' }));
                        }
                        ws.close(4001, 'Unauthorized');
                        return;
                    }

                    currentUserId = userId;
                    ws.userId = userId;
                    users.set(userId, { ws, name: data.name || '友だち', token: token });
                    console.log(`[Register] User standby: ${userId} (${data.name || ''})`);
                    ws.send(JSON.stringify({ type: 'registered', userId: userId }));

                    if (offlineMessageQueue.has(userId)) {
                        const queuedMessages = offlineMessageQueue.get(userId) || [];
                        if (queuedMessages.length > 0 && ws.readyState === WebSocket.OPEN) {
                            console.log(`[Offline Queue] 待受復帰した ${userId} へ保留メッセージ ${queuedMessages.length}件を一括バッチ配信`);
                            ws.send(JSON.stringify({
                                type: 'chat_messages_batch',
                                targetUserId: userId,
                                messages: queuedMessages
                            }));
                        }
                        offlineMessageQueue.delete(userId);
                        saveOfflineQueue();
                    }

                    if (offlineReadQueue.has(userId)) {
                        const queuedReads = offlineReadQueue.get(userId) || [];
                        if (queuedReads.length > 0 && ws.readyState === WebSocket.OPEN) {
                            console.log(`[Offline Read Queue] 待受復帰した ${userId} へ保留既読通知 ${queuedReads.length}件を一括配信`);
                            for (const r of queuedReads) {
                                ws.send(JSON.stringify({
                                    type: 'chat_read',
                                    fromUserId: r.fromUserId,
                                    targetUserId: r.targetUserId,
                                    messageIds: r.messageIds
                                }));
                            }
                        }
                        offlineReadQueue.delete(userId);
                        saveOfflineReads();
                    }
                    return;
                }

                // 2. 着信コール通知
                if (type === 'call_invite') {
                    const targetUserId = data.targetUserId || data.targetId;
                    const fromUserId = data.fromUserId;
                    const timestamp = Number(data.timestamp) || 0;
                    const nonce = (data.nonce || '').trim();

                    const callerUid = ws.userId || currentUserId;
                    if (!callerUid || (fromUserId && callerUid !== fromUserId)) {
                        console.warn(`[Call Invite Rejected] 未認証またはUID不一致の着信要求: callerUid=${callerUid}, fromUserId=${fromUserId}`);
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'auth_error', message: '未認証の接続から着信を発信することはできません' }));
                        }
                        return;
                    }

                    if (timestamp <= 0 || !nonce || nonce.length < 8) {
                        console.warn(`[Call Invite Rejected] timestampまたはnonce未指定の不正パケットを遮断 from ${fromUserId}`);
                        return;
                    }
                    const diff = Math.abs(now - timestamp);
                    if (diff > 35000) {
                        console.warn(`[Call Invite Rejected] タイムスタンプ期限切れ (diff=${diff}ms) from ${fromUserId}`);
                        return;
                    }

                    if (seenInviteNonces.has(nonce)) {
                        console.warn(`[Call Invite Rejected] Nonce重複リプレイ攻撃検知: nonce=${nonce} from ${fromUserId}`);
                        return;
                    }
                    seenInviteNonces.add(nonce);
                    setTimeout(() => { seenInviteNonces.delete(nonce); }, 60000);

                    const targetEntry = users.get(targetUserId);
                    let forwardedViaWs = false;
                    if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                        targetEntry.ws.send(JSON.stringify({
                            type: 'incoming_call',
                            fromUserId: data.fromUserId,
                            fromName: data.fromName,
                            roomId: data.roomId,
                            isVideo: data.isVideo === true || data.isVideo === 'true',
                            timestamp: timestamp || Date.now(),
                            nonce: nonce
                        }));
                        console.log(`[Call Invite] Forwarded via WebSocket from ${data.fromUserId} to ${targetUserId}`);
                        forwardedViaWs = true;
                    }

                    const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get((targetUserId || '').trim());
                    if (targetFcm && targetFcm.fcmToken) {
                        console.log(`[Call Invite] Triggering FCM Push to target: ${targetUserId} (wsOnline=${forwardedViaWs})`);
                        sendIncomingCallPush(targetFcm.fcmToken, {
                            fromUserId: data.fromUserId,
                            fromName: data.fromName,
                            roomId: data.roomId,
                            isVideo: data.isVideo === true || data.isVideo === 'true',
                            timestamp: timestamp || Date.now(),
                            nonce: nonce
                        });
                    }
                    else if (!forwardedViaWs) {
                        console.warn(`[Call Invite Offline] 相手(${targetUserId})はWebSocket切断かつFCMトークン未登録`);
                        ws.send(JSON.stringify({ type: 'call_user_offline', targetUserId: targetUserId }));
                    }
                    return;
                }

                // 3. 着信拒否・キャンセル
                if (type === 'call_cancel' || type === 'call_decline') {
                    const callerUid = ws.userId || currentUserId;
                    if (!callerUid || !data.fromUserId || callerUid !== data.fromUserId) {
                        console.warn(`[Call Cancel Block] 未認証または送信元UID不一致の切断要求を破棄: auth=${callerUid}, packet=${data.fromUserId}`);
                        return;
                    }
                    const targetUserId = data.targetUserId || data.targetId;
                    const targetEntry = users.get(targetUserId);
                    if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                        targetEntry.ws.send(JSON.stringify(data));
                    }
                    return;
                }

                // 4. チャットメッセージ ＆ ECDH鍵交換パケット中継
                if (['chat_message', 'chat_key_ping', 'chat_key_pong'].includes(type)) {
                    if (!currentUserId || !data.fromUserId || data.fromUserId !== currentUserId) {
                        console.warn(`[Security Block] 未認証またはチャット送信元UID偽装を遮断: registered=${currentUserId}, packet=${data.fromUserId}`);
                        return;
                    }

                    if (message.length > 512 * 1024) {
                        console.warn(`[Security Block] 許容サイズ(35MB)超過の巨大メッセージを破棄: ${data.fromUserId}`);
                        return;
                    }

                    const targetUserId = data.targetUserId || data.targetId;
                    const targetEntry = users.get(targetUserId);
                    const senderName = users.get(data.fromUserId)?.name || data.fromName || '友だち';
                    const isMutation = (data.subType === 'unsend' || data.subType === 'edit');
                    const dedupKey = data.messageId ? `${data.fromUserId}:${targetUserId}:${data.messageId}` : '';
                    const alreadyProcessed = dedupKey ? recentChatPacketIds.has(dedupKey) : false;
                    if (dedupKey) {
                        enforceMapSizeCap(recentChatPacketIds, 5000);
                        recentChatPacketIds.set(dedupKey, Date.now());
                    }

                    let sentViaWs = false;
                    if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                        if (!alreadyProcessed) {
                            targetEntry.ws.send(JSON.stringify(data));
                            console.log(`[E2EE Chat] Forwarded encrypted message from ${data.fromUserId} to ${targetUserId} (subType=${data.subType || 'normal'})`);
                        }
                        sentViaWs = true;
                    }

                    // オフライン時、または送信取消・書換え(unsend/edit)時はハーフオープン対策として必ずキュー側にも反映 (No.17対策)
                    if (!sentViaWs || isMutation) {
                        if (!offlineMessageQueue.has(targetUserId)) {
                            enforceMapSizeCap(offlineMessageQueue, 500);
                            offlineMessageQueue.set(targetUserId, []);
                        }
                        const queue = offlineMessageQueue.get(targetUserId);
                        if (data.subType === 'unsend' && data.targetMessageId) {
                            for (let i = queue.length - 1; i >= 0; i--) {
                                if ((queue[i].messageId === data.targetMessageId || queue[i].targetMessageId === data.targetMessageId) && queue[i].fromUserId === data.fromUserId) {
                                    queue.splice(i, 1);
                                }
                            }
                        }
                        else if (data.subType === 'edit' && data.targetMessageId) {
                            for (let i = queue.length - 1; i >= 0; i--) {
                                if (queue[i].subType === 'edit' && queue[i].targetMessageId === data.targetMessageId && queue[i].fromUserId === data.fromUserId) {
                                    queue.splice(i, 1);
                                }
                            }
                        }
                        if (!queue.some(m => m.messageId && m.messageId === data.messageId)) {
                            queue.push(data);
                            if (queue.length > 100) { queue.shift(); }
                            saveOfflineQueue();
                            console.log(`[E2EE Chat Queue] 相手(${targetUserId})宛てキュー保管完了 (subType=${data.subType || 'normal'}, 保留計: ${queue.length}件)`);
                        }
                    }

                    if (type === 'chat_message' && !alreadyProcessed) {
                        const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get((targetUserId || '').trim());
                        if (targetFcm && targetFcm.fcmToken) {
                            sendChatMessagePush(targetFcm.fcmToken, {
                                subType: data.subType || '',
                                targetMessageId: data.targetMessageId || '',
                                fromUserId: data.fromUserId,
                                fromName: senderName,
                                messageId: data.messageId,
                                text: data.text || '',
                                iv: data.iv || '',
                                cipher: data.cipher || '',
                                // VULN-50是正: 4KB上限超過によるプッシュ送信エラーを完全防止
                                hasImage: data.imageBase64 ? 'true' : '',
                                fileUrl: data.fileUrl || '',
                                fileKey: '',
                                fileName: data.fileName || '',
                                fileSize: data.fileSize || '0',
                                senderPubKey: data.senderPubKey || '',
                                senderPubSig: data.senderPubSig || '',
                                timestamp: data.timestamp || Date.now()
                            });
                        }

                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'chat_sent_ack',
                                messageId: data.messageId,
                                timestamp: Date.now()
                            }));
                        }
                    }
                    return;
                }

                // 4.9. 暗号鍵不一致(復号失敗)エラー通知中継
                if (type === 'chat_decrypt_error') {
                    const regUid = (currentUserId || '').trim();
                    const fromUserId = regUid || (data.fromUserId || '').trim();
                    const targetUserId = (data.targetUserId || data.targetId || '').trim();
                    const messageId = (data.messageId || '').trim();
                    if (!targetUserId || !messageId) { return; }

                    const targetEntry = users.get(targetUserId);
                    if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                        targetEntry.ws.send(JSON.stringify({
                            type: 'chat_decrypt_error',
                            fromUserId: fromUserId,
                            targetUserId: targetUserId,
                            messageId: messageId,
                            timestamp: Date.now()
                        }));
                    }
                    return;
                }

                // 5. 既読通知中継
                if (type === 'chat_read') {
                    const regUid = (currentUserId || '').trim();
                    const senderUid = (data.fromUserId || '').trim();
                    if (!regUid || (senderUid && senderUid !== regUid)) {
                        console.warn(`[Security Block] 未認証または既読送信元UID不一致を遮断: registered=${regUid}, packet=${senderUid}`);
                        return;
                    }
                    const fromUserId = regUid;
                    const targetUserId = (data.targetUserId || data.targetId || '').trim();
                    const messageIds = Array.isArray(data.messageIds) ? data.messageIds : (Array.isArray(data.ids) ? data.ids : []);
                    if (!targetUserId || messageIds.length === 0) { return; }

                    const targetEntry = users.get(targetUserId);
                    let forwarded = false;
                    if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                        targetEntry.ws.send(JSON.stringify({
                            type: 'chat_read',
                            fromUserId: fromUserId,
                            targetUserId: targetUserId,
                            messageIds: messageIds
                        }));
                        forwarded = true;
                    }

                    if (!offlineReadQueue.has(targetUserId)) {
                        offlineReadQueue.set(targetUserId, []);
                    }
                    const rq = offlineReadQueue.get(targetUserId);
                    rq.push({
                        fromUserId: fromUserId,
                        targetUserId: targetUserId,
                        messageIds: messageIds,
                        timestamp: Date.now()
                    });
                    if (rq.length > 300) { rq.shift(); }
                    saveOfflineReads();
                    console.log(`[WS Chat Read Store] 相手(${targetUserId})宛ての既読通知をキュー保持 (保留計: ${rq.length}件, WS即時=${forwarded})`);
                    return;
                }

                // 6. 通話ルームJoin
                if (type === 'join') {
                    if (!data.token || !isValidSession(data.token, userId)) {
                        console.warn(`[Security Block] 不正または無効なセッションのWebSocket参加要求を遮断: User=${userId}, Room=${roomId}`);
                        ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized session' }));
                        ws.close(4001, 'Unauthorized session');
                        return;
                    }

                    if (!roomId || typeof roomId !== 'string' || !roomId.includes(userId)) {
                        console.warn(`[Security Block] 権限のない通話ルームへの不正Joinを遮断: User=${userId}, Room=${roomId}`);
                        ws.send(JSON.stringify({ type: 'error', message: 'Forbidden room access' }));
                        ws.close(4003, 'Forbidden room access');
                        return;
                    }

                    if (!rooms.has(roomId)) { rooms.set(roomId, new Set()); }
                    const room = rooms.get(roomId);

                    room.forEach((client) => {
                        if (client.userId === userId && client.ws !== ws) {
                            room.delete(client);
                        }
                    });
                    if (room.size >= 2) {
                        console.warn(`[Security Block] 通話ルーム定員(2名)超過の参加要求を遮断: User=${userId}, Room=${roomId}`);
                        ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
                        return;
                    }

                    currentRoomId = roomId;
                    currentUserId = userId;
                    ws.userId = userId;

                    // VULN-29是正: joinパケット単体での無検証incoming_callおよびFCM自動発火を廃止
                    // （着信通知はcall_inviteによる厳格なタイムスタンプ・Nonce・署名検証シーケンスのみで行う）

                    const isCaller = !!data.isCaller;
                    room.forEach((client) => {
                        if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN) {
                            client.ws.send(JSON.stringify({ type: 'joined', peerId: userId, isCaller: isCaller }));
                            ws.send(JSON.stringify({ type: 'joined', peerId: client.userId, isCaller: !!client.isCaller }));
                        }
                    });

                    room.add({ ws, userId, isCaller });
                    console.log(`[Join] Room: ${roomId}, User: ${userId}, isCaller: ${isCaller}, Count: ${room.size}`);
                    return;
                }

                // 7. WebRTC SDP / ICE / Avatar 同期
                if (['offer', 'answer', 'candidate', 'avatar_sync'].includes(type)) {
                    if (!currentUserId || !currentRoomId) {
                        console.warn(`[Security Block] 未Joinソケットからのシグナリングパケットを遮断: ${type}`);
                        return;
                    }
                    if (message.length > 64 * 1024) {
                        console.warn(`[Security Block] 許容サイズ(64KB)超過のシグナリングパケットを破棄: ${type}`);
                        return;
                    }

                    const senderId = data.userId || data.fromUserId;
                    if (senderId && senderId !== currentUserId) {
                        console.warn(`[Security Block] シグナリングなりすましパケットを遮断: current=${currentUserId}, payloadSender=${senderId}`);
                        return;
                    }
                    // No.10対策: サーバー側で認証済みUIDを強制バインド
                    data.userId = currentUserId;

                    if (rooms.has(currentRoomId)) {
                        const room = rooms.get(currentRoomId);
                        room.forEach((client) => {
                            if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN) {
                                client.ws.send(JSON.stringify(data));
                            }
                        });
                    }
                    return;
                }

                if (type === 'leave') {
                    removeClientFromRoom(ws, currentRoomId, currentUserId);
                }
            }
            catch (e) {
                console.error('JSON parse or forward error:', e.message);
            }
        });

        let isCleanedUp = false;
        const onCloseOrError = () => {
            if (isCleanedUp) { return; }
            isCleanedUp = true;
            clearTimeout(unauthTimeout);
            const count = wsIpConnectionCount.get(wsClientIp) || 1;
            if (count <= 1) { wsIpConnectionCount.delete(wsClientIp); }
            else { wsIpConnectionCount.set(wsClientIp, count - 1); }

            if (currentUserId && users.get(currentUserId)?.ws === ws) {
                users.delete(currentUserId);
                console.log(`[Unregister] Standby disconnected: ${currentUserId}`);
            }
            removeClientFromRoom(ws, currentRoomId, currentUserId);
        };

        ws.on('close', onCloseOrError);
        ws.on('error', onCloseOrError);
    });

    return wss;
}

module.exports = {
    setupWebSocketServer
};

return module.exports;
})({ exports: {} }, {});

// ==================== [Main: server.js] ====================
// 変更日時：2026年10月31日 12時20分
// WebRTC Signaling Server エントリポイント (モジュール分割リファクタリング版)
// 【AI厳守ルール】本ファイルまたは ./modules/*.js を変更した際は、必ず `node scripts/bundle_server_for_github.js` を実行し、
// `server/server_single_for_github.js` に最新の変更内容を完全上書き反映すること（詳細は「サーバー更新指示書.txt」参照）。
// 構成モジュール:
//  - ./modules/stateStore.js          : セッション・オフラインキュー・FCMトークン・永続化ストア
//  - ./modules/pushAndMail.js         : Firebase Admin FCMプッシュ送信・GAS/SMTPメール送信
//  - ./modules/httpAuthRoutes.js      : 2段階認証OTP・セッション更新/再バインド・FCM登録API
//  - ./modules/httpChatAndFileRoutes.js: チャット保留取得・既読・メッセージ送信・暗号化ファイル転送API
//  - ./modules/wsSignaling.js         : WebSocket P2P通話シグナリング ＆ E2EEチャット中継

const http = require('http');
const { ipConnectionTracker, enforceMapSizeCap, flushAllStoresSync } = __requireModule('./modules/stateStore');
const { handleAuthRoutes } = __requireModule('./modules/httpAuthRoutes');
const { handleChatAndFileRoutes } = __requireModule('./modules/httpChatAndFileRoutes');
const { setupWebSocketServer } = __requireModule('./modules/wsSignaling');

const port = process.env.PORT || 3000;

// HTTPサーバー (セキュリティヘッダー・レート制限・REST APIディスパッチ)
const server = http.createServer(async (req, res) =>
{
    // セキュリティヘッダー付与
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'none'");

    // VULN-52是正: CORSワイルドカード(*)を撤廃し、特定信頼オリジンまたはネイティブアプリ直接通信のみ許可
    const origin = req.headers['origin'];
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
    if (origin && allowedOrigins.includes(origin))
    {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Device-Uid, X-Target-Uid');
    }

    if (req.method === 'OPTIONS')
    {
        if (origin && allowedOrigins.includes(origin))
        {
            res.writeHead(204);
            res.end();
            return;
        }
        res.writeHead(403);
        res.end();
        return;
    }

    // VULN-37是正: 偽装X-Forwarded-For対策。プロキシ環境下で直近ホストまたはソケットIPを優先評価
    const rawForwarded = req.headers['x-forwarded-for'];
    const forwardedIps = rawForwarded ? rawForwarded.split(',').map(s => s.trim()).filter(Boolean) : [];
    const clientIp = (forwardedIps.length > 0 ? forwardedIps[forwardedIps.length - 1] : null) || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let ipRecord = ipConnectionTracker.get(clientIp);
    if (!ipRecord || now > ipRecord.resetTime)
    {
        enforceMapSizeCap(ipConnectionTracker, 5000);
        ipRecord = { count: 0, resetTime: now + 60000 };
        ipConnectionTracker.set(clientIp, ipRecord);
    }
    ipRecord.count++;
    if (ipRecord.count > 60)
    {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'アクセス過多のため一時的に制限されています。少し待って再試行してください' }));
        return;
    }

    const url = req.url || '';

    // ヘルスチェック
    if (req.method === 'GET' && (url === '/' || url === '/health'))
    {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
            status: 'ok',
            server: 'CellPhone Signaling Server'
        }));
        return;
    }

    // 認証・FCMトークン系APIのディスパッチ
    if (await handleAuthRoutes(req, res, url))
    {
        return;
    }

    // チャット・暗号化ファイル転送系APIのディスパッチ
    if (await handleChatAndFileRoutes(req, res, url))
    {
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
});

// WebSocketサーバーのバインド
setupWebSocketServer(server);

// グレースフルシャットダウン
process.on('SIGTERM', () =>
{
    console.log('[SIGTERM] シグナル受信: データを同期保存してシャットダウンします');
    flushAllStoresSync();
    process.exit(0);
});

process.on('SIGINT', () =>
{
    console.log('[SIGINT] シグナル受信: データを同期保存してシャットダウンします');
    flushAllStoresSync();
    process.exit(0);
});

// サーバー起動
server.listen(port, () =>
{
    console.log(`Signaling & Auth OTP Server listening on port ${port}`);
});

